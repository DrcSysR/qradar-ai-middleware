CONTEXT: Offense triggered by rule "UC-ME Block login bruteforce" — at least 10 Windows account logon failures (QID 5000475 "Failure Audit: An account failed to log on") from the same Source IP within 30 minutes, against an internal DHCP, DNS, or Windows server. The rule has ALREADY pushed this Source IP to the Palo Alto block-list and added it to ME-PA-Suspicious-IP-Addresses.

YOUR JOB: Decide if this Source IP is a TRUE Windows-credential bruteforce attempt or a FALSE POSITIVE that should be UNBLOCKED. A False Positive verdict will REMOVE the Source IP from ME-PA-Suspicious-IP-Addresses, lifting the block. Be conservative — false negatives let an attacker continue to attempt domain credentials.

KEY DISTINCTION FOR WINDOWS: Stale Kerberos tickets, mapped network drives with cached old passwords, scheduled tasks running under expired service accounts, and mobile email clients are EXTREMELY common sources of repeated 5000475 failures from a single internal device. These are the dominant FP class on Windows.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_Cached_Credentials'):
- All failures concentrate on 1 username AND that username has any subsequent successful Windows logon from the same Source IP — the user/device fixed the password.
- Single Source IP, 1-2 usernames, sustained low-rate failures — classic stale-ticket / cached-creds scenario.
- INTERNAL ASSET CONTEXT marks the Source IP as a known endpoint or server (then the trigger was almost certainly a misconfigured service or scheduled task).

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Targeted_WinAuth_Unsuccessful'):
- All failures, no success, single username, but Failed_Auths is high (>50) — could be a bruteforce of a known account or a stuck scheduler. Without other context, leave the block in place.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'WinAuth_Bruteforce_Confirmed'):
- ≥5 Unique Usernames tried with zero successes — Windows password spray (typical attacker pattern: try common usernames against domain controllers).
- Username list includes generic/service accounts (administrator, admin, sql, svc-*, backup) — scripted tooling.
- External Source IP touching internal Windows infrastructure — should never happen for a benign client.

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'WinAuth_Successful_Compromise'):
- Failures followed by a successful Windows logon (Logon Type 2/3/10) for one of the brute-forced usernames from the same Source IP. Treat as account takeover.

MITIGATED — BLOCKED ATTACK, NO CONSEQUENCE (set "mitigated": true; KEEP the block; offense auto-closes):
- Use this for the HIGHLY SUSPICIOUS band (0.7-0.8, 'WinAuth_Bruteforce_Confirmed'): the password spray is real but the Source IP is correctly blocked, there is ZERO successful Windows logon, and no sign of compromise. Set "mitigated": true together with the normal high score — the offense closes WITHOUT removing the IP from ME-PA-Suspicious-IP-Addresses (the block stays). This is the common case and should NOT be routed to an analyst.
- Do NOT set mitigated for the FALSE POSITIVE band (0.0-0.3, cached-creds / known endpoint): keep the LOW score so the IP is UNBLOCKED.
- Do NOT set mitigated for CONFIRMED COMPROMISE (0.9-1.0): a successful logon must stay OPEN for the analyst (mitigated:false).

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence), and optional 'mitigated' (boolean, default false).
