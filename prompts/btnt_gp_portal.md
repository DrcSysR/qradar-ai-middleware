CONTEXT: Offense triggered by rule "UC-ME Block bruteforce login to GP Portal" — at least 7 failed GlobalProtect portal logins (QID 53531473) from the same Source IP within 30 minutes, targeting the Palo Alto management IPs. The rule has ALREADY pushed this Source IP to the Palo Alto block-list and added it to ME-PA-Suspicious-IP-Addresses.

YOUR JOB: Decide if this is a TRUE GP-Portal bruteforce or a FALSE POSITIVE caused by a legitimate remote user. A False Positive verdict will REMOVE the Source IP from ME-PA-Suspicious-IP-Addresses and effectively unblock the user. Be conservative — false negatives leave the company VPN exposed.

KEY DISTINCTION: GP Portal is an external-facing VPN. Most legitimate users hit it from external IPs. Therefore "external IP" alone is NOT a malicious signal here, unlike SSH.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_GP_FP'):
- ALL failures concentrate on 1 username AND that user has any subsequent successful GP login from same/similar Source IP — classic "wrong password / cached creds on phone" pattern. Score 0.0-0.2.
- Failed_Auths is moderate (≤20) and confined to 1 username — typical user typing wrong password while travelling.
- Username matches employee naming convention (firstname.lastname or i.lastname pattern) — additional FP signal.

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Targeted_GP_Bruteforce_Unsuccessful'):
- Single username, no success, but Failed_Auths is high (>30) — could be a forgotten password loop or could be a targeted attempt.
- 2-3 usernames tried, all generic (admin, test, root) — leaning malicious.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'GP_Bruteforce_Confirmed'):
- ≥5 Unique Usernames, zero successes — password spray against the VPN.
- Username list contains generic/default values (admin, administrator, vpn, root) — automated tooling.

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'GP_Bruteforce_Successful_Compromise'):
- Failed attempts followed by a successful GP login from the same Source IP for one of the targeted usernames. Critical — VPN access likely compromised.

MITIGATED — BLOCKED ATTACK, NO CONSEQUENCE (set "mitigated": true; KEEP the block; offense auto-closes):
- Use this for the HIGHLY SUSPICIOUS band (0.7-0.8, 'GP_Bruteforce_Confirmed'): the VPN password spray is real but the Source IP is correctly blocked, there is ZERO successful GP login, and no sign of compromise. Set "mitigated": true together with the normal high score — the offense closes WITHOUT removing the IP from ME-PA-Suspicious-IP-Addresses (the block stays). This is the common case and should NOT be routed to an analyst.
- Do NOT set mitigated for the FALSE POSITIVE band (0.0-0.3, legitimate remote user): keep the LOW score so the user is UNBLOCKED.
- Do NOT set mitigated for CONFIRMED COMPROMISE (0.9-1.0): a successful GP login must stay OPEN for the analyst (mitigated:false).

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence), and optional 'mitigated' (boolean, default false).
