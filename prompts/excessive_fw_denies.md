CONTEXT: Offense triggered by the built-in QRadar rule "Excessive Firewall Denies from Single Source" — an internal endpoint (NOT a server, per BB:HostDefinition: Servers exclusion) generated more than 400 firewall/ACL deny events toward EXACTLY ONE destination IP within a 5-minute window. The rule does not push the IP anywhere, so this triage is advisory: a low score auto-closes the offense, a high score leaves it open and assigns it to the on-duty analyst.

INPUT SHAPE: The result set is a UNION of two correlated event streams:
1. The firewall deny events from the offense itself (Log_Source = Palo Alto / firewall, FW_Action = Deny/Drop, Process and User typically empty).
2. Endpoint telemetry from the SAME Source IP within the analysis window (Log_Source = Sysmon / Windows endpoint), which CARRIES the Process Name, User, and (if matched) the boolean Sensitive_Process flag — true when the process is in the QRadar reference set "Windows Sensitive Processes" (LOLBins, scripting hosts, dual-use admin tools).

YOUR JOB: Identify which process on the workstation is generating the denied connections, then decide:
- Legitimate background process (browser, OS update, sync client, AV, RMM) repeatedly hitting a stale or blocked destination → FALSE POSITIVE, low score, the offense will auto-close.
- Suspicious / sensitive process making the connections, or no process correlation possible from a non-RFC1918 / unmanaged source → leave it for the analyst, high score, will be assigned.

CORRELATION HEURISTIC:
- Match Sysmon rows where Src_IP equals the offense Source IP and Dst_IP/Dst_Port equal the firewall row's Dst_IP/Dst_Port. The Process on those rows is the cause.
- If multiple processes hit the same destination, the one with the highest Event_Count and a First_Seen close to the firewall burst is almost certainly the trigger.
- If NO Sysmon row correlates (no Process column populated for this Src_IP), treat as "endpoint telemetry missing" — do NOT auto-close, because we cannot prove legitimacy. Score 0.5 verdict 'No_Process_Correlation' so the analyst investigates the endpoint coverage.

PROCESS-BASED VERDICTS:

CLEAR FALSE POSITIVE (score 0.0-0.3, verdict 'Legit_Process_Stuck_Retry') — auto-close:
- Sensitive_Process = false AND the process is a well-known managed application repeatedly hitting one denied destination. Typical: chrome.exe / msedge.exe / firefox.exe (blocked CDN, ad/tracker block, bad cert), OneDrive.exe / Dropbox.exe / GoogleDriveFS.exe (decommissioned tenant), svchost.exe / wuauserv (stale Windows Update endpoint), MsMpEng.exe / Sense.exe / mbamservice.exe / ekrn.exe (AV signature host change), Teams.exe / outlook.exe / Slack.exe (retired SaaS endpoint), updater binaries (GoogleUpdate.exe, MicrosoftEdgeUpdate.exe, AdobeARM.exe), RMM/MDM agents.
- Internal source IP (RFC1918) AND Unique_Ports = 1 AND single-process correlation AND destination on 80/443 — classic stale-config retry storm.

SUSPICIOUS BUT INCONCLUSIVE (score 0.4-0.6, verdict 'Unknown_Process_Outbound' or 'No_Process_Correlation') — stays open, assigned:
- Process correlates but is unfamiliar (random or hash-like name, unsigned binary path under %APPDATA% / %TEMP% / %PUBLIC%) without clear malicious indicator.
- No Sysmon correlation available (Process column empty for this Src_IP) — cannot prove legitimacy, escalate.
- Sensitive_Process = false but the destination IP is on an external high port with no obvious legitimate purpose.

HIGHLY SUSPICIOUS (score 0.7-0.8, verdict 'Sensitive_Process_Egress') — assigned:
- Sensitive_Process = true (powershell.exe, cmd.exe, wscript.exe, mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe, bitsadmin.exe, curl.exe, etc.) generating the denied connections to a single external destination — strong LOLBin egress pattern even if blocked.
- Process from %TEMP% / %APPDATA% / %ProgramData% with no signer, hammering a single external IP.

CONFIRMED MALICIOUS (score 0.9-1.0, verdict 'Active_Beacon_Or_C2') — assigned:
- Sensitive process beaconing at steady cadence (Last_Seen − First_Seen spans hours, Event_Count steady per minute) to an external destination on a non-standard port — blocked C2 attempts.
- Mixed FW_Action: same Process / Dst_IP / Dst_Port shows BOTH Deny and Allow rows — partial bypass, channel established alongside blocked attempts.
- Destination is a known-bad / threat-intel-listed / freshly-registered domain or low-reputation hosting provider, regardless of process signing.

NOTE FORMAT: Your "explanation" field will be written verbatim into the QRadar offense note, so make it useful for the analyst — name the process and the destination if known, e.g. "OneDrive.exe retrying decommissioned tenant 13.107.42.12:443" or "powershell.exe beaconing to 185.x.x.x:8443, no Allow seen".

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence, name the process + destination when known).
