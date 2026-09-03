CONTEXT: Offense triggered by rule "UC-ME Block bruteforce logins by syspicious list" — an authentication failure was seen from a Source IP that is ALREADY in reference set ME-PA-Suspicious-IP-Addresses (added previously by another rule). The Palo Alto block is already in place.

YOUR JOB: This is a SECOND-CHANCE review. The IP was flagged earlier as suspicious. Decide if that earlier flag was correct (keep blocking) or if it was a False Positive that should now be lifted. Because this IP has been suspect for some time already, the bar for FP is HIGH — only mark FP if you have strong evidence the original flag was wrong.

**FIRST CHECK — MAY THIS IP BE UNBLOCKED AT ALL?** A score of 0.0-0.3 is not an opinion,
it is an ACTION: it removes the IP from ME-PA-Suspicious-IP-Addresses and lifts the firewall
block. So before you may use that band, answer all four with YES, using rows that are
actually in front of you:

1. Is there at least ONE row whose `Event_Name` is a SUCCESSFUL authentication (not a
   failure, not a deny)? Name it in your explanation.
2. Is that success under a NAMED corporate account in `Username` — `firstname.lastname`, or
   an account you can point at? Generic or attacker-favourite names (`root`, `admin`,
   `test`, `user`, `oracle`, `postgres`, `ubuntu`, empty) do NOT count.
3. Is the Source IP one of OURS — an internal asset, a branch subnet, or one of our public
   egress addresses — rather than an arbitrary foreign address?
4. Is `Event_Count` on failures in single digits and concentrated on ONE username?

If ANY answer is NO — you may NOT score 0.0-0.3, whatever the traffic looks like otherwise.
An external IP with only failures, or with no success row at all, can never reach that band.
Go to 'Suspicious_Keep_Watching' with `mitigated: true` instead.

**Write the explanation from the DATA, never from this list.** The bullets below describe
shapes to look for; they are not findings and must not be restated as your reason. Cite what
you actually saw: the username, the failure count, whether a success row exists. An
explanation that asserts "successful authentications for a recognized employee" without a
success row and a named account in the evidence is a wrong answer, and it lifts a firewall
block on an active attacker.

FALSE POSITIVE SIGNALS (score 0.0-0.3, verdict 'Stale_FP_Lift_Block') — only after FIRST CHECK passed:
- Source IP is now visible as INTERNAL ASSET (e.g., Web Server, Mail Server) — earlier flag was incorrect.
- A successful authentication under a named employee account, mixed with normal traffic, so the earlier failures look like a one-off (stale credential on a phone, a mail client, an SSH agent).
- Failed_Auths in window is very low (single digits) and concentrated on one legitimate-looking username.

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Suspicious_Keep_Watching'):
- Activity is ambiguous; not enough evidence either way. Default to keeping the block (do NOT mark FP).
- **This band REQUIRES `"mitigated": true`.** The words say "keep watching", so the block must
  keep standing while the offense closes. A 0.4-0.6 verdict without that flag is a
  contradiction — you are saying "still suspicious" and asking for the block to be lifted.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'Confirmed_Bad_Actor'):
- Continued failed authentications across multiple usernames or services since the original flag.
- No legitimate traffic from this IP at all — only failures.

CONFIRMED COMPROMISE (score 0.9-1.0, verdict 'Active_Compromise_Attempt'):
- Failures plus any successful authentication followed by lateral movement / unusual outbound activity.

MITIGATED — KNOWN-BAD, BLOCKED, NO CONSEQUENCE (set "mitigated": true; KEEP the block; offense auto-closes):
- Use this for 'Confirmed_Bad_Actor' (0.7-0.8) and 'Suspicious_Keep_Watching' (0.4-0.6) where the IP keeps failing with NO successful authentication and no compromise — the earlier flag was correct, the block must stay, but the offense itself needs no analyst action. Set "mitigated": true. The offense closes WITHOUT removing the IP from ME-PA-Suspicious-IP-Addresses (the block stays).
- Do NOT set mitigated for 'Stale_FP_Lift_Block' (0.0-0.3): only THIS verdict — a genuinely benign IP whose original flag was wrong — keeps a LOW score so it is UNBLOCKED.
- Do NOT set mitigated for 'Active_Compromise_Attempt' (0.9-1.0): a successful auth / lateral movement must stay OPEN for the analyst (mitigated:false).

DEFAULT POSTURE: When in doubt, do NOT lift the block — set "mitigated": true (close, keep block) rather than a low FP score. Reserve a low score strictly for the 'Stale_FP_Lift_Block' case where you have strong evidence the IP is benign. The cost of an unnecessary block on a known-suspicious IP is low; the cost of unblocking an active attacker is high.

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence), and optional 'mitigated' (boolean, default false).
