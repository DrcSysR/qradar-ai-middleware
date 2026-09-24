CONTEXT: Offense triggered by rule #118289 "Login Failure to Expired Account" — QRadar CRE rule on Windows event 4625 with sub-status "Expired Password" (`An account failed to log on: Expired Password`). It fires on a SINGLE event. The offense entity is the USERNAME. This rule does NOT push anything to a block-list and there is NO refset cleanup: a low score simply auto-closes the offense; nothing is unblocked. Input columns: `Time`, `Acct` (username), `Src` (source IP), `Dst` (destination host), `LogonType`, `LogSource`, `Event`, `Attempts`.

BASE RATE (measured 2026-09-24): 221 open offenses, 939 events in total (~4 per offense), median age 17 days, every one of them a named employee whose Active Directory password had simply expired — logging into their OWN workstation (Src `127.0.0.1`, logon type 2) or validated through the MFA appliance `172.17.61.173` / a domain controller (`172.17.61.112`, `.6`, `.252`, logon type 3). That is password-expiry hygiene for the IT helpdesk, not a security event.

PRE-FILTER (important): the AQL has ALREADY removed the entire benign base rate. It returns rows ONLY when at least one of these is true:
  (a) `Src` is OUTSIDE our address space (not RFC1918 and not loopback) — an expired credential is being tried from the Internet;
  (b) `Acct` looks like an admin, service or machine account (`adm*`, `*admin*`, `svc*`, `sa`, `*$`).
If the input is EMPTY, everything in this offense was a named user with an expired password from an internal or loopback source: score 0.1, verdict 'Benign_Expired_Password_User'.

**FIRST CHECK — IS `Src` EXTERNAL? Do this before anything else.**
1. Scan every row's `Src`. Is any of them outside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`?
2. If YES: someone OUTSIDE the network holds a (now expired) password of a real employee. The attempt FAILED and the account cannot be used with that password, so there is no compromise — but the credential is evidently known outside, which is worth a human look (possible leak, password reuse, or a former employee's stale device). Score **0.7**, verdict 'Expired_Credential_Tried_From_External', and name the account and the external IP in the explanation. Keep OPEN (this band does not auto-close).
3. Exception that lowers step 2 to **0.3**: the external `Src` is one of OUR OWN public egress addresses — `188.163.216.96/28`, `82.207.23.25`, `212.1.102.0/24`, `212.1.103.0/24`, `168.119.209.0/24`, `158.255.89.122` — that is a roaming employee behind our NAT/VPN, i.e. the benign case again.

ADMIN / SERVICE ACCOUNT (score 0.4, verdict 'Expired_Service_Account_Password'): `Acct` matches the admin/service/machine patterns and `Src` is internal. A service whose password expired is an operations problem (it will keep failing and may lock out or break something), not an attack. Auto-closes, but NAME the account and the source host in the explanation so it can be fixed.

REAL RISK — KEEP OPEN (score 0.7-0.8, verdict 'Expired_Credential_Tried_From_External'): external source per FIRST CHECK; or an admin/service account tried from an external source (both conditions) — score 0.8.

There is NO 'mitigated' band here and NO 'compromise' band: an expired password by definition cannot succeed, so the ceiling is 0.8. Do not invent lateral movement, spraying or brute force from this evidence — those have their own rules (UC-01-1, 148444) and the count here is a handful of events.

VALID VERDICT STRINGS — emit exactly one of: 'Benign_Expired_Password_User' | 'Expired_Service_Account_Password' | 'Expired_Credential_Tried_From_External'

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence naming the account and source). Do NOT default to a high score just because the offense fired — the base rate of this rule is 100% benign hygiene; only the pre-filtered external/service-account cases reach you.
