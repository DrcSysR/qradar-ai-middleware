CONTEXT: Offense triggered by rule "UC-ME-22 Port Scanning Blacklisting" — at least 10 connections to common service ports (22, 23, 137-139, 445, 3389, 8291, 8728, 8729) from the same Source IP within 30 minutes, targeting the DMZ. The rule has ALREADY pushed this Source IP to ME-PA-Suspicious-IP-Addresses and the Palo Alto block-list.

YOUR JOB: Decide if this Source IP is a TRUE port scanner / reconnaissance tool, or a FALSE POSITIVE that should be UNBLOCKED. A False Positive verdict will REMOVE the IP from ME-PA-Suspicious-IP-Addresses. Be conservative.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_Scanner_FP'):
- Source IP belongs to internal infrastructure (vulnerability scanner, monitoring system, asset discovery tool) — INTERNAL ASSET CONTEXT will indicate this.
- Unique_Targets is low (1-2) and Unique_Ports is low (1-2) — not a scan, just retries to a single service.
- Firewall_Action shows "Allow" for legitimate services and the destinations are this IP's normal workload.

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Limited_Probe'):
- Unique_Targets ≥ 3 OR Unique_Ports ≥ 3 but volume is low. Could be a misconfigured tool or early reconnaissance.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'Active_Port_Scan'):
- Unique_Targets ≥ 5 OR Unique_Ports ≥ 5 with sustained event volume.
- External Source IP touching multiple internal services it has no business reaching.
- Pattern of sequential port hits (typical Nmap/Masscan signature).

CONFIRMED RECON / EXPLOITATION (score 0.9-1.0, verdict 'Recon_With_Exploit_Attempt'):
- Wide port spread followed by sustained traffic on a specific service (suggests scan → exploit pivot).
- Successful connections (Firewall_Action=Allow with established session) on services that should be blocked from this Source IP.

If INTERNAL ASSET CONTEXT lists the Source IP as known infrastructure (scanner, monitoring), heavily weight toward FP.

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence).
