# Starter placeholder.
# Later we will connect MaxMind GeoLite2 database here.

def enrich_ip(source_ip):
    return {
        "source_ip": source_ip,
        "country": "Unknown",
        "city": "Unknown",
        "asn": "Unknown",
        "isp": "Unknown"
    }
