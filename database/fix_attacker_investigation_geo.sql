DO $$
DECLARE
    geo_rel TEXT;
    country_col TEXT;
    city_col TEXT;
    asn_col TEXT;
    country_expr TEXT;
    city_expr TEXT;
    asn_expr TEXT;
    join_sql TEXT;
    create_sql TEXT;
BEGIN
    SELECT quote_ident(c.table_schema) || '.' || quote_ident(c.table_name)
    INTO geo_rel
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON c.table_schema = t.table_schema
     AND c.table_name = t.table_name
    WHERE c.table_schema = 'public'
      AND c.column_name = 'source_ip'
      AND c.table_name NOT IN (
          'events',
          'attacker_investigation_events',
          'attacker_investigation_summary',
          'attacker_investigation_timeline',
          'attacker_web_session_replay'
      )
      AND EXISTS (
          SELECT 1
          FROM information_schema.columns x
          WHERE x.table_schema = c.table_schema
            AND x.table_name = c.table_name
            AND x.column_name IN ('country', 'geo_country', 'country_name')
      )
    ORDER BY
      CASE
        WHEN c.table_name ILIKE '%reputation%' THEN 1
        WHEN c.table_name ILIKE '%geo%' THEN 2
        WHEN c.table_name ILIKE '%profile%' THEN 3
        ELSE 10
      END,
      c.table_name
    LIMIT 1;

    IF geo_rel IS NULL THEN
        RAISE NOTICE 'No geo/profile relation found. Investigation Center will keep raw_log fallback.';
        join_sql := '';
        country_expr := 'NULL::text';
        city_expr := 'NULL::text';
        asn_expr := 'NULL::text';
    ELSE
        RAISE NOTICE 'Using geo/profile source: %', geo_rel;

        SELECT column_name INTO country_col
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = replace(split_part(geo_rel, '.', 2), '"', '')
          AND column_name IN ('country', 'geo_country', 'country_name')
        ORDER BY CASE column_name
            WHEN 'country' THEN 1
            WHEN 'geo_country' THEN 2
            WHEN 'country_name' THEN 3
            ELSE 10
        END
        LIMIT 1;

        SELECT column_name INTO city_col
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = replace(split_part(geo_rel, '.', 2), '"', '')
          AND column_name IN ('city', 'geo_city', 'city_name')
        ORDER BY CASE column_name
            WHEN 'city' THEN 1
            WHEN 'geo_city' THEN 2
            WHEN 'city_name' THEN 3
            ELSE 10
        END
        LIMIT 1;

        SELECT column_name INTO asn_col
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = replace(split_part(geo_rel, '.', 2), '"', '')
          AND column_name IN ('asn', 'as_org', 'isp', 'org', 'organization')
        ORDER BY CASE column_name
            WHEN 'asn' THEN 1
            WHEN 'as_org' THEN 2
            WHEN 'isp' THEN 3
            WHEN 'org' THEN 4
            WHEN 'organization' THEN 5
            ELSE 10
        END
        LIMIT 1;

        country_expr := CASE
            WHEN country_col IS NOT NULL THEN format('NULLIF(%I::text, '''')', country_col)
            ELSE 'NULL::text'
        END;

        city_expr := CASE
            WHEN city_col IS NOT NULL THEN format('NULLIF(%I::text, '''')', city_col)
            ELSE 'NULL::text'
        END;

        asn_expr := CASE
            WHEN asn_col IS NOT NULL THEN format('NULLIF(%I::text, '''')', asn_col)
            ELSE 'NULL::text'
        END;

        join_sql := format(
            'LEFT JOIN (
                SELECT DISTINCT ON (source_ip)
                    source_ip,
                    %s AS geo_country,
                    %s AS geo_city,
                    %s AS geo_asn
                FROM %s
                WHERE source_ip IS NOT NULL
                ORDER BY source_ip
            ) g ON g.source_ip = e.source_ip',
            country_expr,
            city_expr,
            asn_expr,
            geo_rel
        );
    END IF;

    create_sql := format($VIEW$
CREATE OR REPLACE VIEW attacker_investigation_events AS
SELECT
    e.id,
    e.timestamp AS event_time,
    e.source_ip,
    e.service,
    e.event_type,
    COALESCE(NULLIF(e.attack_type, ''), 'Unknown') AS attack_type,
    COALESCE(NULLIF(e.username, ''), '-') AS username,
    e.method,
    e.path,
    e.command,
    e.user_agent,
    e.payload,
    COALESCE(e.risk_score, 0) AS risk_score,
    COALESCE(NULLIF(e.severity, ''), 'Low') AS severity,
    COALESCE(NULLIF(e.mitre_id, ''), '-') AS mitre_id,
    COALESCE(NULLIF(e.mitre_tactic, ''), '-') AS mitre_tactic,
    COALESCE(NULLIF(e.mitre_technique, ''), '-') AS mitre_technique,

    COALESCE(
        g.geo_country,
        NULLIF(e.raw_log->>'country', ''),
        NULLIF(e.raw_log->>'geo_country', ''),
        CASE
            WHEN e.source_ip IN ('127.0.0.1', '::1', 'localhost') THEN 'Localhost'
            WHEN e.source_ip LIKE '10.%%'
              OR e.source_ip LIKE '172.%%'
              OR e.source_ip LIKE '192.168.%%' THEN 'Private/Internal'
            ELSE 'Unknown'
        END
    ) AS country,

    COALESCE(
        g.geo_city,
        NULLIF(e.raw_log->>'city', ''),
        NULLIF(e.raw_log->>'geo_city', ''),
        CASE
            WHEN e.source_ip IN ('127.0.0.1', '::1', 'localhost') THEN 'Local Machine'
            WHEN e.source_ip LIKE '10.%%'
              OR e.source_ip LIKE '172.%%'
              OR e.source_ip LIKE '192.168.%%' THEN 'Internal Network'
            ELSE 'Unknown'
        END
    ) AS city,

    COALESCE(
        g.geo_asn,
        NULLIF(e.raw_log->>'asn', ''),
        NULLIF(e.raw_log->>'as_org', ''),
        NULLIF(e.raw_log->>'org', ''),
        'Unknown'
    ) AS asn,

    e.raw_log
FROM events e
%s;
$VIEW$, join_sql);

    EXECUTE create_sql;

    INSERT INTO audit_logs(actor, action, status, details, created_at)
    VALUES (
        'system',
        'attacker_investigation_geo_enrichment_fixed',
        'success',
        jsonb_build_object('geo_source', COALESCE(geo_rel, 'raw_log_only')),
        NOW()
    );

    RAISE NOTICE 'attacker_investigation_events geo enrichment updated.';
END $$;
