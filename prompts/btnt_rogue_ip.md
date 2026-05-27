CONTEXT: Offense triggered by rule "UC-ME Deny continiously bruteforce from rogue IP" — repeated authentication failures (≥3 within 60 minutes) against usernames on the bruteforce-target list (UC-ME Bruteforce target usersname list), from a Source IP that is NOT in known internal server networks. QRadar indexes this offense by SOURCE IP (offense_type SourceIP), and the offense_source is that attacking IP. The rule has ALREADY pushed this Source IP to ME-PA-Suspicious-IP-Addresses, so the Palo Alto block is in place.

INPUT: events aggregated for the offense's Source IP over the window — the usernames it tried, the event names (SSH/Windows auth failures, firewall denies), the target IPs, and any SUCCESSFUL authentications. A single Source IP touching many usernames is normal for this rule.

YOUR JOB: Decide if this Source IP is a TRUE bruteforce / botnet attacker or a FALSE POSITIVE (e.g., a legitimate user with stale credentials). This rule does NOT trigger automated refset cleanup, so the block stays in place regardless of your verdict (the radar manages its TTL); your verdict drives offense triage only.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_User_Error'):
- Failures concentrate on ONE username AND that username has a subsequent SUCCESSFUL login from the same Source IP — credentials are valid, this was a typo / stale-cache storm.
- Total Failed_Auths is small (3-10), single username, and the Source IP looks like a known user device or internal asset.

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Single_Source_Targeting'):
- All failures, no success, moderate volume against 1-2 usernames from one external/unknown Source IP — could be a stuck client or an early-stage attempt.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'Rogue_IP_Bruteforce_Confirmed'):
- Multiple usernames tried (≥3, especially generic: root, admin, ubuntu, user, gpadmin, oracle, postgres, test) with ZERO successes — classic external credential bruteforce.
- High failure volume and/or firewall denies mixed with the auth failures — the IP is hammering services and being blocked.
- External Source IP touching internal infrastructure with only failures.

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'Successful_Compromise'):
- Failed attempts FOLLOWED by a SUCCESSFUL login from this Source IP for any of the targeted usernames.

If INTERNAL ASSET CONTEXT marks the Source IP as a known internal asset, treat that as a strong FP signal.

MITIGATED — BLOCKED ATTACK, NO CONSEQUENCE (set "mitigated": true; offense auto-closes; block stays):
- Use this for the HIGHLY SUSPICIOUS / INCONCLUSIVE bands (0.4-0.8) where there are ONLY failures (auth failures and/or firewall denies) and NO successful login from this Source IP — the attack was contained and the IP is already blocked. Set "mitigated": true together with the honest high score so the offense closes without bothering the analyst. (The radar's escalating PA action keeps the IP blocked and manages its TTL.)
- Do NOT set mitigated for 'Successful_Compromise' (0.9-1.0): a successful login must stay OPEN for the analyst (mitigated:false).
- A clear benign FP (0.0-0.3, user error) keeps its LOW score and auto-closes normally — no need for mitigated.

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence), and optional 'mitigated' (boolean, default false).
