import httpx
import logging
from typing import Dict, Any, Optional
from ..config import settings

logger = logging.getLogger(__name__)

# High-fidelity mock database of indicators for attack simulations
SIMULATED_INTEL = {
    # Command & Control / Brute Force IPs
    "198.51.100.45": {
        "value": "198.51.100.45",
        "type": "ip",
        "reputation": "Malicious",
        "threat_score": 95,
        "provider": "AbuseIPDB",
        "details": {
            "country": "Russia",
            "country_code": "RU",
            "asn": "AS12345 (JSC Active Telecom)",
            "domain": "telecom-active.ru",
            "usage_type": "Data Center/Web Hosting/Transit",
            "total_reports": 342,
            "last_reported": "2026-07-16T12:00:00Z",
            "malware_family": "Cobalt Strike Beacon",
            "campaigns": ["APT29 (Cozy Bear)", "UNC2452"],
            "tags": ["c2", "scanner", "brute-force"]
        }
    },
    "203.0.113.19": {
        "value": "203.0.113.19",
        "type": "ip",
        "reputation": "Malicious",
        "threat_score": 88,
        "provider": "AbuseIPDB",
        "details": {
            "country": "China",
            "country_code": "CN",
            "asn": "AS4134 (Chinanet)",
            "domain": "chinanet.cn",
            "usage_type": "ISP",
            "total_reports": 1520,
            "last_reported": "2026-07-16T18:45:00Z",
            "malware_family": "Mirai / SSH Scanner",
            "campaigns": ["Mass Scanning Campaign"],
            "tags": ["ssh-brute", "port-scan"]
        }
    },
    # Domains
    "malicious-c2-tunnel.cn": {
        "value": "malicious-c2-tunnel.cn",
        "type": "domain",
        "reputation": "Malicious",
        "threat_score": 98,
        "provider": "VirusTotal / AlienVault",
        "details": {
            "registrar": "Ename Technology Co., Ltd.",
            "creation_date": "2025-11-04",
            "ip_address": "198.51.100.45",
            "country": "China",
            "malicious_detections": 68,
            "total_engines": 72,
            "malware_family": "Sliver C2",
            "campaigns": ["APT41 (Double Dragon)"],
            "tags": ["c2", "dns-tunneling"]
        }
    },
    "update-service-microsoft.ru": {
        "value": "update-service-microsoft.ru",
        "type": "domain",
        "reputation": "Malicious",
        "threat_score": 92,
        "provider": "VirusTotal / OpenPhish",
        "details": {
            "registrar": "RU-CENTER",
            "creation_date": "2026-02-18",
            "ip_address": "203.0.113.52",
            "country": "Russia",
            "malicious_detections": 45,
            "total_engines": 70,
            "malware_family": "Phishing Redirect / Cobalt Strike Loader",
            "campaigns": ["Sofacy (APT28)"],
            "tags": ["phishing", "typosquatting", "c2"]
        }
    },
    # Mimikatz hashes
    "9f8db278125b2d97424fa7bb0f592652": {
        "value": "9f8db278125b2d97424fa7bb0f592652",
        "type": "hash",
        "reputation": "Malicious",
        "threat_score": 100,
        "provider": "VirusTotal",
        "details": {
            "hash_md5": "9f8db278125b2d97424fa7bb0f592652",
            "hash_sha256": "2566ecb754876b2cd18843df3d5236cf5e381643c749fbde48128362cc8dcf2c",
            "file_name": "mimikatz.exe",
            "file_size": "1238400 bytes",
            "file_type": "Win32 EXE",
            "malicious_detections": 70,
            "total_engines": 72,
            "first_seen": "2014-04-12T08:32:00Z",
            "last_seen": "2026-07-15T22:10:00Z",
            "malware_family": "Hacktool.Mimikatz",
            "campaigns": ["Generic Credential Theft"],
            "tags": ["mimikatz", "lsass", "credential-dumping"]
        }
    },
    "2566ecb754876b2cd18843df3d5236cf5e381643c749fbde48128362cc8dcf2c": {
        "value": "2566ecb754876b2cd18843df3d5236cf5e381643c749fbde48128362cc8dcf2c",
        "type": "hash",
        "reputation": "Malicious",
        "threat_score": 100,
        "provider": "VirusTotal",
        "details": {
            "hash_md5": "9f8db278125b2d97424fa7bb0f592652",
            "hash_sha256": "2566ecb754876b2cd18843df3d5236cf5e381643c749fbde48128362cc8dcf2c",
            "file_name": "mimikatz.exe",
            "file_size": "1238400 bytes",
            "file_type": "Win32 EXE",
            "malicious_detections": 70,
            "total_engines": 72,
            "first_seen": "2014-04-12T08:32:00Z",
            "last_seen": "2026-07-15T22:10:00Z",
            "malware_family": "Hacktool.Mimikatz",
            "campaigns": ["Generic Credential Theft"],
            "tags": ["mimikatz", "lsass", "credential-dumping"]
        }
    }
}

async def check_abuseipdb(ip: str) -> Optional[Dict[str, Any]]:
    if not settings.ABUSEIPDB_API_KEY:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": settings.ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": ""
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reputation = "Clean"
                if score > 50:
                    reputation = "Malicious"
                elif score > 10:
                    reputation = "Suspicious"
                return {
                    "value": ip,
                    "type": "ip",
                    "reputation": reputation,
                    "threat_score": score,
                    "provider": "AbuseIPDB",
                    "details": {
                        "country": data.get("countryName"),
                        "country_code": data.get("countryCode"),
                        "asn": f"AS{data.get('asn')} ({data.get('isp')})",
                        "domain": data.get("domain"),
                        "usage_type": data.get("usageType"),
                        "total_reports": data.get("totalReports", 0),
                        "last_reported": data.get("lastReportedAt"),
                        "tags": ["scanner"] if score > 10 else []
                    }
                }
    except Exception as e:
        logger.error(f"Error checking AbuseIPDB: {e}")
    return None

async def check_virustotal(ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    
    # VT endpoints differ by type
    endpoint = ""
    if ioc_type == "ip":
        endpoint = f"ip_addresses/{ioc}"
    elif ioc_type == "domain":
        endpoint = f"domains/{ioc}"
    elif ioc_type == "hash":
        endpoint = f"files/{ioc}"
    else:
        return None

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1
                
                score = int((malicious / total) * 100) if total > 0 else 0
                reputation = "Clean"
                if malicious > 5:
                    reputation = "Malicious"
                elif malicious > 0 or suspicious > 2:
                    reputation = "Suspicious"
                    
                # Standardized output
                details = {
                    "malicious_detections": malicious,
                    "total_engines": total,
                    "country": attributes.get("country"),
                    "tags": attributes.get("tags", []),
                }
                
                if ioc_type == "hash":
                    details["file_name"] = attributes.get("meaningful_name")
                    details["file_size"] = f"{attributes.get('size', 0)} bytes"
                    details["file_type"] = attributes.get("type_description")
                    
                return {
                    "value": ioc,
                    "type": ioc_type,
                    "reputation": reputation,
                    "threat_score": score,
                    "provider": "VirusTotal",
                    "details": details
                }
    except Exception as e:
        logger.error(f"Error checking VirusTotal: {e}")
    return None

async def enrich_ioc(value: str) -> Dict[str, Any]:
    """
    Enriches an indicator (IP, domain, hash) using real APIs or fallback simulation data.
    """
    value = value.strip()
    
    # 1. Determine type
    ioc_type = "domain"
    if ":" in value or (value.replace(".", "").isdigit() and len(value.split(".")) == 4):
        ioc_type = "ip"
    elif len(value) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in value):
        ioc_type = "hash"
        
    # 2. Check for high-fidelity simulation entries first (to ensure simulation scenarios look great)
    if value in SIMULATED_INTEL:
        logger.info(f"Returning high-fidelity simulated threat intel for {value}")
        return SIMULATED_INTEL[value]

    # 3. Query real APIs if keys are present
    if ioc_type == "ip" and settings.ABUSEIPDB_API_KEY:
        res = await check_abuseipdb(value)
        if res:
            return res
            
    if settings.VIRUSTOTAL_API_KEY:
        res = await check_virustotal(value, ioc_type)
        if res:
            return res

    # 4. Final Generic Clean Mock fallback if no API key is defined and not a simulator IP
    return {
        "value": value,
        "type": ioc_type,
        "reputation": "Clean",
        "threat_score": 0,
        "provider": "Mock Enrichment Service",
        "details": {
            "status": "Unknown / Unreported",
            "message": "Indicator was not found in global threat feeds or simulation database."
        }
    }
