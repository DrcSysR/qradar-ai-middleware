CONTEXT: Offense triggered by rule "UC-ME Block login bruteforce" — at least 10 Windows account logon failures (QID 5000475 "Failure Audit: An account failed to log on") from the same Source IP within 30 minutes, against an internal DHCP, DNS, or Windows server. The rule has ALREADY pushed this Source IP to the Palo Alto block-list and added it to ME-PA-Suspicious-IP-Addresses.

YOUR JOB: Decide if this Source IP is a TRUE Windows-credential bruteforce attempt or a FALSE POSITIVE that should be UNBLOCKED. A False Positive verdict will REMOVE the Source IP from ME-PA-Suspicious-IP-Addresses, lifting the block. Be conservative — false negatives let an attacker continue to attempt domain credentials.

**FIRST CHECK — RDS CONNECTION BROKER SELF-AUTH NOISE (V-SRV01). Do this BEFORE anything else.**
Answer these in order:
1. Is Source_IP `172.17.61.41` (V-SRV01, the RD Connection Broker of the RDS farm)?
2. Are ALL failing usernames in the data either `V-SRV01` or `V-SRV01$` (the server's own name, with or without `$`)? Failure rows with an EMPTY/None username count as consistent ONLY if they are 'Kerberos pre-authentication failed' or 'Windows Filtering Platform' rows (QRadar does not extract the account name for those — they are the KDC side of the same noise and broadcast drops). Successful logons of other accounts may be present — they do not change the answer; a failure of ANY other named username does.
3. Are the failure events Windows logon failures / Kerberos pre-authentication failures only (no SSH, no firewall, no VPN events)?
If 1, 2 AND 3 are all YES → score 0.1, verdict 'Benign_RDS_Broker_Selfauth', mitigated false. Stop here. Measured 06.10.2026: the broker service `tssdis.exe` (NETWORK SERVICE) passes an explicit credential `MODERN\V-SRV01` (no `$`) on every user RDP brokering, against itself and the session hosts (e.g. V-SRV06). NTLM fails with 0xC0000064 (no such user), the KDC retries as `V-SRV01$` and fails with 0x18. It tracks user logon volume (hundreds per hour in work hours), has run since at least August, and is NOT an attack — a server IP must not sit in the block-list.
If any of 1-3 is NO, ignore this check and apply the bands below.

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

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above, including 'Benign_RDS_Broker_Selfauth'), 'explanation' (≤15 words, single sentence), and optional 'mitigated' (boolean, default false).
