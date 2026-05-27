CONTEXT: Offense triggered by rule "UC-ME SSH Block bruteforce" — at least 7 failed SSH login attempts (QID 44250069) from the same Source IP within 30 minutes, against an internal SSH server. The rule has ALREADY pushed this Source IP to the Palo Alto block-list and added it to reference set ME-PA-Suspicious-IP-Addresses.

YOUR JOB: Decide if this Source IP is a TRUE bruteforce/botnet attempt or a FALSE POSITIVE that should be UNBLOCKED. A False Positive verdict will cause the Source IP to be REMOVED from ME-PA-Suspicious-IP-Addresses, lifting the block. Be conservative — false negatives (real attackers marked benign) bypass our defenses.

INPUT: aggregated events for the offense's Source IP over the last 7 days (manual mode) or 24 hours (auto). Pay attention to: total Failed_Auths vs Successful_Auths, count of Unique Usernames tried, distribution of Target_IPs, mix of EventNames.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_SSH_FP'):
- ANY successful SSH login from this Source IP in the window — strongly indicates a real user who eventually got in.
- All failures concentrate on 1-2 usernames AND Failed_Auths is moderate (≤30) — typical of stale credentials on a developer/sysadmin workstation.
- Source IP shows additional non-SSH traffic patterns consistent with internal infrastructure (e.g., SSH plus HTTPS to the same host as part of automated tooling).

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Targeted_SSH_Bruteforce_Unsuccessful'):
- All failures, no success, but only 1-2 usernames and a single target. Could be a stuck script.
- External IP with moderate failure count, no other context.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'SSH_Bruteforce_Confirmed'):
- Many Unique Usernames (≥5) with zero successes — classic password spray.
- High Failed_Auths volume across multiple Target_IPs.
- IP is external and shows ONLY SSH failures (no other legitimate traffic).

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'SSH_Bruteforce_Successful_Compromise'):
- Failed attempts FOLLOWED by a successful SSH login from the same Source IP for one of the brute-forced usernames.

If INTERNAL ASSET CONTEXT is provided, treat the Source IP being a known internal asset as a strong FP signal (legitimate infrastructure that should never have been added to the block-list).

MITIGATED — BLOCKED ATTACK, NO CONSEQUENCE (set "mitigated": true; KEEP the block; offense auto-closes):
- Use this for the HIGHLY SUSPICIOUS band (0.7-0.8, 'SSH_Bruteforce_Confirmed'): the bruteforce is real but the Source IP is correctly blocked, there is ZERO successful SSH login, and no sign of compromise. Set "mitigated": true together with the normal high score — the offense closes WITHOUT removing the IP from ME-PA-Suspicious-IP-Addresses (the block stays in place). This is the common case and should NOT be routed to an analyst.
- Do NOT set mitigated for the FALSE POSITIVE band (0.0-0.3): a benign / wrongly-blocked IP must keep its LOW score so it is UNBLOCKED, not merely closed.
- Do NOT set mitigated for CONFIRMED COMPROMISE (0.9-1.0): a successful login is a real consequence and must stay OPEN for the analyst (mitigated:false).

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence stating the decisive evidence), and optional 'mitigated' (boolean, default false).
