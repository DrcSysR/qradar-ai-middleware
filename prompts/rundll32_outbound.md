CONTEXT: Offense triggered by rule "RunDLL32 Outbound Network Connection" — the Windows
binary `rundll32.exe` opened a network connection (Sysmon EventID 3). `rundll32.exe` is a
legitimate Windows LOLBin whose whole job is to host DLLs, so many Windows components and
line-of-business apps make network calls through it. It is ALSO a favourite of malware,
which uses it to run a malicious DLL under a trusted process name.

INPUT: aggregated connections for this offense — `Host` (workstation), `Proc_Path` (full
path of the rundll32 binary), `Dst`/`Dport` (external destination), `Acct` (user),
`Conns` (count). Internal (RFC1918) destinations and OUR OWN public ranges have already
been filtered out by the query, because measurement showed ~99% of this rule's volume is
rundll32 hosting a business-app DLL talking to internal MS SQL (1433/3030) or to our own
published service — pure noise. What reaches you is genuine external egress only.

**FIRST CHECK — IS THE BINARY ITSELF LEGITIMATE? Do this before judging the destination.**
The only legitimate locations for this binary are `C:\Windows\System32\rundll32.exe` and
`C:\Windows\SysWOW64\rundll32.exe` (case-insensitive).
If `Proc_Path` is ANYWHERE ELSE — `\Temp\`, `\AppData\`, `\ProgramData\`, a user profile,
a removable drive, or any nested folder — this is a MASQUERADING binary using a trusted
name, and the destination no longer matters. Emit `score: 0.95`,
`verdict: "Masquerading_Rundll32_Binary"` and name the path and host. Do not continue.

Once the path is confirmed genuine, judge the DESTINATION:

Verdict Benign_Windows_Telemetry (score 0.2): destination belongs to Microsoft/Azure
(e.g. 20.x, 40.x, 48.x, 4.247.x, 57.15x.x, 13.x, 52.x) over port 443. This is Windows
Update / Office / Defender / telemetry hosted through rundll32 — the dominant benign
pattern here, seen across dozens of unrelated workstations.

Verdict Benign_App_Update (score 0.3): destination is a well-known CDN or cloud provider
(CloudFront, Akamai, Fastly, AWS) over 80 or 443 with a handful of connections — typical
application-updater behaviour. Plain HTTP is slightly unusual but common for updaters.

Verdict Suspicious_Rundll32_Egress (score 0.5): raw IP at a generic VPS/hosting provider,
or an unusual port, with low connection counts — anomalous but not conclusive.

Verdict Suspected_Rundll32_C2 (score 0.8): NEEDS A HUMAN. Any of: non-standard high port
to an uncategorised host; a steady, repeating connection count consistent with periodic
beaconing; destination in a country or hosting range with no business relationship; or
the same external IP contacted by rundll32 across MULTIPLE unrelated workstations (that
pattern means a shared implant, not a per-user app).

Weigh breadth deliberately: ONE workstation reaching a cloud endpoint is ordinary; the
SAME odd destination from several hosts is the strongest signal in this data set.
Remember a score above 0.6 keeps the offense OPEN for an analyst, while <=0.6 auto-closes.

OUTPUT: respond with ONLY a single JSON object, no other text:
{"score": <float 0.0-1.0>, "verdict": "<one of the verdict strings above>", "explanation": "<one sentence, max 15 words>"}
