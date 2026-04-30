CONTEXT: Offense triggered by rule "UC-ME Deny continiously bruteforce from rogue IP" — at least 3 authentication failures within 60 minutes against a Username that is on the bruteforce-target list (UC-ME Bruteforce target usersname list), with the Source IP NOT belonging to known internal server networks. The offense entity is a USERNAME, not an IP. The rule populates ME-PA-Suspicious-IP-Addresses with each contributing Source IP.

YOUR JOB: Decide if the activity targeting this username is a TRUE password-spray / bruteforce attempt, or a FALSE POSITIVE (e.g., a legitimate user with stale credentials trying repeatedly). This verdict drives offense triage and analyst assignment — this offense does NOT trigger automated refset cleanup.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_User_Error'):
- All failures come from a SINGLE Source IP that looks like a known user device (consistent OUI / consistent ASN over time).
- Total Failed_Auths is small (3-10) and concentrated on one username.
- A successful login by the same username from any of the source IPs in the window — credentials are likely legitimate, this was a typo storm.

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Single_Source_Targeting'):
- All failures from one external/unknown Source IP, moderate volume, no success.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'Distributed_Bruteforce_Or_Botnet'):
- Failures originate from MULTIPLE distinct Source IPs (≥3) — strong botnet signature.
- Geographically/ASN-diverse Source IPs hammering the same username.
- Username is high-value (admin, service account) and zero successes.

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'Successful_Compromise'):
- Failures followed by a successful login for this Username from any of the attacking Source IPs.

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence).
