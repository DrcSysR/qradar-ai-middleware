CONTEXT: Offense triggered by rule "UC-ME A large number of failed login attempts were detected under the same username" — at least 30 authentication failures (QIDs 44250069, 44250168, 44250910, 53531473) for the same Username within a 12-hour window, with Source IP NOT in Web/SSH/Mail server networks. The offense entity is a USERNAME. This rule does NOT populate the suspicious-IP refset directly.

YOUR JOB: Triage the failures targeting this username — distinguish a real bruteforce / botnet from a noisy benign user. This verdict drives offense triage; refset cleanup is not automated for this rule.

**FIRST CHECK — LINUX PAM FALL-THROUGH (domain login on an SSSD/AD Linux host). Do this BEFORE anything else.**
Answer these in order, per (Source_IP → Target_IP) pair:
1. Is Source_IP internal (RFC1918: 10.x, 172.16-31.x, 192.168.x)?
2. Are the failures Linux/SSH auth events ('Authentication Failure', 'User space authentication' failure, pam_unix) AND does the SAME pair also carry 'Accepted Password for User' / session-start events for the SAME username?
3. Is the failure count roughly EQUAL to the accepted/session count for that pair (within ~10%)?
If 1, 2 AND 3 are all YES → score 0.1, verdict 'Benign_PAM_Fallthrough', mitigated false. Stop here. Every interactive SSH login of a domain user to an SSSD-joined Linux host logs one `pam_unix(sshd:auth): authentication failure` (the local-password module fails first) and then `Accepted password` from the SAME sshd process a second later — one "failure" per successful session. A developer opening 200 sessions in two hours (e.g. DVL43 172.17.64.43 → VIDEO 192.168.48.207, 01.10.2026) trips the rule with ZERO real failures. Do NOT invent external sources: count only the Source_IP values actually present in the data.
If any of 1-3 is NO, ignore this check and apply the bands below.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Benign_Stale_Credentials'):
- All failures from 1-2 Source IPs that look like the same user device (mobile, workstation) — stale cached password retrying constantly.
- A successful login for this Username appears in the data from one of the same source IPs — credentials are valid, just intermittent device sync issue.
- Username is a regular employee account AND failure event names suggest "wrong password" rather than "account does not exist".

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Sustained_Single_Source'):
- High failure count from a single external Source IP, no success — could be scripted bruteforce, could be a stuck client.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'Distributed_Bruteforce_Or_Botnet'):
- Failures originate from MULTIPLE Source IPs (≥3), with NO successful authentications anywhere — distributed bruteforce / botnet password spray against this account.
- Bonus signal: usernames typical of automated lists (admin, root, postgres, oracle, test) — indicates external automated tooling.

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'Successful_Bruteforce_Compromise'):
- Failures followed by a successful authentication for this Username from one of the attacking Source IPs.

MITIGATED — CONTAINED, NO CONSEQUENCE (set "mitigated": true; offense auto-closes):
- Use this for the HIGHLY SUSPICIOUS / INCONCLUSIVE bands (0.4-0.8, 'Distributed_Bruteforce_Or_Botnet' / 'Sustained_Single_Source') where there are ONLY failures and NO successful authentication for this Username anywhere — the spray was contained, no account was taken over. Set "mitigated": true together with the honest high score so the offense closes without bothering the analyst. (Contributing Source IPs are handled by the bruteforce/botnet block-list rules; the radar manages their TTL.)
- Do NOT set mitigated for 'Successful_Bruteforce_Compromise' (0.9-1.0): a successful login must stay OPEN for the analyst (mitigated:false).
- A clear benign FP (0.0-0.3) keeps its LOW score and auto-closes normally — no need for mitigated.

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above, including 'Benign_PAM_Fallthrough'), 'explanation' (≤15 words, single sentence), and optional 'mitigated' (boolean, default false).
