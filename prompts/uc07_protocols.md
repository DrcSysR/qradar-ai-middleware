CONTEXT: Offense triggered by UC-07-1 — an internal host (the Source IP) used an UNTRUSTED / cleartext protocol (typically HTTP on port 80, but also FTP/Telnet/TFTP/SMTP-cleartext) to transfer data. The offense entity is the SOURCE IP (one of our own devices). This rule does NOT push the IP to any block-list and there is NO refset cleanup: a low score simply auto-closes the offense, it does NOT unblock anything. Input is aggregated by Source, Dest, Port, App (Palo Alto App-ID), with Sessions and Bytes per pair, ordered by Bytes_Sent (potential exfil first).

PRE-FILTER (important): the AQL now returns ONLY genuinely untrusted/cleartext transfer protocols — `ftp`, `ftp-data`, `tftp`, `telnet`, `rlogin`, `rsh`, `rexec`, `smtp` (cleartext), and `unknown-tcp`/`unknown-udp`/`unknown-p2p`. Normal HTTP/web-browsing, TLS/SSL, STUN, Viber, QUIC, OS/vendor updates and DNS are filtered out BEFORE you see them, so they produce NO rows. If the input is empty, score 0.1 'Benign_Cleartext_Traffic'. If you DO receive rows, the protocol itself is already noteworthy — weigh the destination (internal/legacy zone vs arbitrary external) and volume to decide between an accepted legacy use (lower) and a risky external transfer (higher).

YOUR JOB: Decide whether this is the DOMINANT false positive — legitimate software that simply uses cleartext (OS/app updates, certificate validation, captive-portal checks, plain web browsing to CDNs) — or a REAL risk: bulk cleartext EXFILTRATION to an external/unknown host, or use of FTP/Telnet/unknown protocols to arbitrary destinations. This rule is very noisy; the overwhelming majority are benign legitimate cleartext, so bias toward closing unless there is concrete exfil/odd-protocol signal. The App-ID field is the strongest discriminator.

NETWORK MAP (hard anchors):
- Internal/trusted: `172.17.0.0/16`, `192.168.48.0/21`, `192.168.16.0/21` (PL branch), `172.20.22.0/23` (VPN), `172.17.200.0/23`, `192.168.100.0/24` (Hikvision cams). Everything else RFC1918 = guest/untrusted-internal.
- A Dest INSIDE these ranges = internal cleartext (low risk, often device/IoT/management). A Dest OUTSIDE (public Internet) is where exfil risk lives.

BENIGN APP-IDs / DESTINATIONS (treat as FP):
- `ms-update`, `windows-update`, `apple-update`, `google-update`, `adobe-update` and similar updater App-IDs over port 80 — OS/vendor patching legitimately uses HTTP.
- `web-browsing` / `http` to well-known CDNs and vendors: Akamai (`23.x`, `2.16.x`, `104.64-127.x`), Fastly (`151.101.x`, `199.232.x`), Cloudflare, Google, Microsoft, AWS CloudFront — plain HTTP content delivery.
- `ocsp`, `crl`, certificate-validation HTTP (CRL/OCSP are HTTP by design), captive-portal / connectivity checks (msftconnecttest, connectivitycheck.gstatic, captive.apple.com), NTP-adjacent, software telemetry.
- Modest byte volumes typical of browsing/updates.

FALSE POSITIVE (score 0.0-0.3, verdict 'Benign_Cleartext_Traffic'):
- App-ID is an updater (`ms-update` etc.) or `web-browsing`/`http` to a CDN/vendor as above — even with large Bytes_Received (a 1.4 MB Windows Update download over 80 is normal).
- Internal-to-internal cleartext (Dest in our subnets), management/IoT.
- CRL/OCSP/captive-portal/connectivity checks.

SUSPICIOUS / INCONCLUSIVE (score 0.4-0.6, verdict 'Unusual_Cleartext_Transfer'):
- Cleartext to an unrecognised external host but modest volume and a normal-looking App-ID (`web-browsing`) — could be an obscure-but-legit site. Auto-closes.

REAL RISK — KEEP OPEN (score 0.7-0.9, verdict 'Cleartext_Exfil_or_Risky_Protocol'):
- Large Bytes_Sent OUTBOUND to a single EXTERNAL, non-CDN/unknown host over cleartext — possible data exfiltration (weigh Bytes_Sent ≫ Bytes_Received to an arbitrary destination).
- App-ID = `ftp`, `telnet`, `tftp`, `smtp` (cleartext), or `unknown-tcp`/`unknown-udp` to an external host — risky/odd protocol, not normal corporate traffic.
- Sustained bulk internal→external transfer over port 80 to an IP with no CDN/vendor reputation.

CONFIRMED MALICIOUS (score 0.9-1.0, verdict 'Cleartext_Exfil_or_Risky_Protocol'): clear large-volume outbound cleartext transfer to a hostile/unknown external host, or interactive Telnet/FTP to an arbitrary external host.

There is NO 'mitigated' band here (no block was applied). A benign FP keeps its low score and auto-closes; a real exfil/risky-protocol case keeps a high score and stays OPEN for the analyst.

VALID VERDICT STRINGS — emit exactly one of: 'Benign_Cleartext_Traffic' | 'Unusual_Cleartext_Transfer' | 'Cleartext_Exfil_or_Risky_Protocol'

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence stating the decisive evidence). Do NOT default to a high score just because the offense fired — be highly skeptical; this rule's base rate is benign.
