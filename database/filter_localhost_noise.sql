CREATE OR REPLACE FUNCTION ignore_localhost_honeypot_events()
RETURNS trigger AS $$
BEGIN
    IF NEW.source_ip IN ('127.0.0.1', '::1', 'localhost') THEN
        RETURN NULL;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ignore_localhost_honeypot_events ON events;

CREATE TRIGGER trg_ignore_localhost_honeypot_events
BEFORE INSERT ON events
FOR EACH ROW
EXECUTE FUNCTION ignore_localhost_honeypot_events();
