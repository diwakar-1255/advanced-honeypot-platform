# Starter placeholder.
# Later we will connect AbuseIPDB, VirusTotal free tier, and OTX here.

def check_reputation(source_ip):
    return {
        "source_ip": source_ip,
        "abuse_score": 0,
        "vt_score": 0,
        "is_tor": False,
        "is_proxy": False
    }
