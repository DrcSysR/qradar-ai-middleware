CONTEXT: Offense triggered by rule "UC-ME A large number of failed login attempts were detected under the same username" — at least 30 authentication failures (QIDs 44250069, 44250168, 44250910, 53531473) for the same Username within a 12-hour window, with Source IP NOT in Web/SSH/Mail server networks. The offense entity is a USERNAME. This rule does NOT populate the suspicious-IP refset directly.

YOUR JOB: Triage the failures targeting this username — distinguish a real bruteforce / botnet from a noisy benign user. This verdict drives offense triage; refset cleanup is not automated for this rule.

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

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence).
