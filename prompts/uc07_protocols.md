CONTEXT: Offense triggered by UC-07-1 — an internal host (the Source IP) used an UNTRUSTED / cleartext protocol (typically HTTP on port 80, but also FTP/Telnet/TFTP/SMTP-cleartext) to transfer data. The offense entity is the SOURCE IP (one of our own devices). This rule does NOT push the IP to any block-list and there is NO refset cleanup: a low score simply auto-closes the offense, it does NOT unblock anything. Input is aggregated by Source, Dest, Port, App (Palo Alto App-ID), with Sessions and Bytes per pair, ordered by Bytes_Sent (potential exfil first).

PRE-FILTER (important): the AQL now returns ONLY genuinely untrusted/cleartext transfer protocols — `ftp`, `ftp-data`, `tftp`, `telnet`, `rlogin`, `rsh`, `rexec`, `smtp` (cleartext), and `unknown-tcp`/`unknown-udp`/`unknown-p2p`. Normal HTTP/web-browsing, TLS/SSL, STUN, Viber, QUIC, OS/vendor updates and DNS are filtered out BEFORE you see them, so they produce NO rows. If the input is empty, score 0.1 'Benign_Cleartext_Traffic'. If you DO receive rows, the protocol itself is already noteworthy — weigh the destination (internal/legacy zone vs arbitrary external) and volume to decide between an accepted legacy use (lower) and a risky external transfer (higher).

YOUR JOB: Decide whether this is the DOMINANT false positive — legitimate software that simply uses cleartext (OS/app updates, certificate validation, captive-portal checks, plain web browsing to CDNs) — or a REAL risk: bulk cleartext EXFILTRATION to an external/unknown host, or use of FTP/Telnet/unknown protocols to arbitrary destinations. This rule is very noisy; the overwhelming majority are benign legitimate cleartext, so bias toward closing unless there is concrete exfil/odd-protocol signal. The App-ID field is the strongest discriminator.

NETWORK MAP (hard anchors):
- Internal/trusted: `172.17.0.0/16`, `192.168.48.0/21`, `192.168.16.0/21` (PL branch), `172.20.22.0/23` (VPN), `172.17.200.0/23`, `192.168.100.0/24` (Hikvision cams). Everything else RFC1918 = guest/untrusted-internal.
- **`172.18.0.0/16` = guest / BYOD Wi-Fi and the conveniq edge fleet.** Personal phones and laptops, NOT corporate workstations. There is no corporate data on these devices to exfiltrate, and their traffic is consumer messaging/social/streaming by design. See FIRST CHECK.
- A Dest INSIDE these ranges = internal cleartext (low risk, often device/IoT/management). A Dest OUTSIDE (public Internet) is where exfil risk lives.

**FIRST CHECK — IS THE SOURCE A GUEST/BYOD DEVICE? Do this BEFORE anything else.**
1. Read the `Source` field. Is it inside `172.18.0.0/16`?
2. If **YES** — this is a personal device on guest Wi-Fi. It holds no corporate data, so "exfiltration" is not a coherent verdict for it. Cap the score at **0.3**, verdict `Benign_Cleartext_Traffic`, and say in your explanation that the source is a guest/BYOD host. Do NOT continue to the REAL RISK / CONFIRMED MALICIOUS sections.
3. The ONLY exception that lets you go above 0.3 for a `172.18.x` source: a **sustained bulk outbound transfer** — `Bytes_Sent` above ~50 MB to ONE external destination, with `Bytes_Sent` clearly exceeding `Bytes_Received`. Interactive `ftp`/`telnet` to an arbitrary external host also qualifies. Session counts, port variety, and "unknown" App-IDs on their own do NOT.
4. Do not be talked into a high score by the offense chain name (`IRC Connections`, `Local UDP Scanner Detected`, `Traffic End`, `Reset Both`, `Session Denied`). Those are Palo Alto's guesses at unrecognised consumer app traffic, not evidence.

CONSUMER APP DESTINATIONS — `unknown-tcp`/`unknown-udp` here is NORMAL (treat as FP):
Palo Alto labels a proprietary messaging/VoIP protocol it cannot decode as `unknown-tcp`/`unknown-udp`. That label describes App-ID's ignorance, not the traffic's intent. When the destination belongs to a consumer platform, the unknown label carries NO risk signal:
- Telegram — `149.154.160.0/20`, `91.108.0.0/16`
- Meta (Facebook / WhatsApp / Instagram) — `157.240.0.0/16`, `31.13.0.0/16`, `179.60.192.0/22`; port 5222 is WhatsApp/XMPP
- Google / YouTube — `142.250.0.0/15`, `172.217.0.0/16`, `216.58.192.0/19`, `74.125.0.0/16`
- Apple — `17.0.0.0/8`; Microsoft/Skype, Zoom, Viber, Discord, Signal, TikTok
- Local ISP CDN and mobile-operator ranges serving the same apps
Also benign regardless of App-ID: DNS/DHCP to the local gateway (ports 53/67/68), SSDP/mDNS/UPnP multicast (port 1900, 5353), and NAT keepalive/IPSec (ports 500/4500). Symmetric or download-heavy byte counts (`Bytes_Received` ≥ `Bytes_Sent`) confirm ordinary app use — exfiltration is by definition upload-heavy.

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
Every bullet here requires a CORPORATE source (see FIRST CHECK — a `172.18.x` source cannot reach this section) AND concrete volume or protocol evidence, not merely an "unknown" App-ID.
- Large Bytes_Sent OUTBOUND to a single EXTERNAL, non-CDN/unknown host over cleartext — possible data exfiltration (weigh Bytes_Sent ≫ Bytes_Received to an arbitrary destination).
- App-ID = `ftp`, `ftp-data`, `telnet`, `tftp`, `rlogin`, `rsh`, `rexec` or cleartext `smtp` to an EXTERNAL host — an interactive/transfer protocol with no place in corporate traffic. These qualify on their own.
- `unknown-tcp`/`unknown-udp` to an external host qualifies ONLY when the destination is not a consumer platform from the list above AND `Bytes_Sent` is substantial and exceeds `Bytes_Received`. Unknown + chatty + low-volume + consumer destination = `Benign_Cleartext_Traffic`, not exfil. This bullet was the dominant false positive on this rule — apply it strictly.
- Sustained bulk internal→external transfer over port 80 to an IP with no CDN/vendor reputation.

CONFIRMED MALICIOUS (score 0.9-1.0, verdict 'Cleartext_Exfil_or_Risky_Protocol'): clear large-volume outbound cleartext transfer to a hostile/unknown external host, or interactive Telnet/FTP to an arbitrary external host.

There is NO 'mitigated' band here (no block was applied). A benign FP keeps its low score and auto-closes; a real exfil/risky-protocol case keeps a high score and stays OPEN for the analyst.

VALID VERDICT STRINGS — emit exactly one of: 'Benign_Cleartext_Traffic' | 'Unusual_Cleartext_Transfer' | 'Cleartext_Exfil_or_Risky_Protocol'

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence stating the decisive evidence). Do NOT default to a high score just because the offense fired — be highly skeptical; this rule's base rate is benign.
