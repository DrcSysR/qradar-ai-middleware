CONTEXT: Offense triggered by UC-05-1 — an internal host (the Source IP) sent DNS (port 53, App-ID `dns-base`/`dns`) to a server that is NOT one of our corporate DNS resolvers. The offense entity is the SOURCE IP (one of our own devices). This rule does NOT push the IP to any block-list and there is NO refset cleanup: a low score simply auto-closes the offense, it does NOT unblock anything. The input is aggregated by Source, DNS_Server (the queried resolver), App, with Queries and Bytes per pair.

PRE-FILTER (important): the AQL already EXCLUDES known public/ISP resolvers (Google, Cloudflare, Quad9, OpenDNS), AWS Route53, and our own DC/forwarders, AND keeps only rows whose average Bytes_Sent-per-query exceeds ~300 bytes (the tunneling signature). So benign resolver/forwarder traffic and normal small DNS will produce NO rows at all. If you DO receive rows, they already survived that filter — but still apply judgment (a one-off thick query to a reputable host can be benign). If the input is empty/near-empty, score 0.1 'Benign_Public_Resolver'.

YOUR JOB: Decide whether this is the DOMINANT false positive — a device using a benign public/ISP resolver (cached Wi-Fi config, BYOD/phone with a preconfigured public DNS, a domain controller / DNS forwarder resolving public names directly) — or a REAL threat: DNS tunneling, rogue-DNS redirection, or C2 over DNS. This rule is extremely noisy; the overwhelming majority are benign misconfiguration, so bias toward closing unless there is a concrete tunneling/rogue signal.

NETWORK MAP (hard anchors):
- Internal/trusted: `172.17.0.0/16` (primary LAN), `192.168.48.0/21`, `192.168.16.0/21` (Poland branch; DCs `192.168.16.3/.9/.15` run modernpl.local), `172.20.22.0/23` (VPN), `172.17.200.0/23` (remote DC), `192.168.100.0/24` (Hikvision cams).
- A Source that is a DOMAIN CONTROLLER or DNS forwarder (e.g. the PL DCs `192.168.16.3/.9/.15`, or HQ DNS) querying a public resolver is a forwarder doing its job — benign.
- Everything else inside RFC1918 = guest/untrusted-internal (BYOD, IoT) — cached public DNS on these is the classic Wi-Fi-roaming FP.

KNOWN-BENIGN PUBLIC / ISP RESOLVERS (treat the DNS_Server as benign if it is one of these or another reputable resolver):
- Google `8.8.8.8`, `8.8.4.4`; Cloudflare `1.1.1.1`, `1.0.0.1`; Quad9 `9.9.9.9`, `149.112.112.112`; OpenDNS `208.67.222.222`, `208.67.220.220`.
- Cloud/authoritative resolvers a forwarder may hit directly: AWS Route 53 (`205.251.192.0/23`), major CDN/cloud DNS.
- Reputable Ukrainian ISP resolvers (Ukrtelecom, Kyivstar, Datagroup, Lanet, etc.).

FALSE POSITIVE (score 0.0-0.3, verdict 'Benign_Public_Resolver'):
- DNS_Server is a well-known public/ISP resolver from the list above (or clearly one of that class), with normal small per-query bytes (tens to low hundreds of bytes) and modest query counts. Cached/preconfigured DNS on a roaming Wi-Fi/BYOD device.
- Source is one of OUR domain controllers / forwarders resolving public names. (e.g. `192.168.16.3` → AWS Route 53 = forwarder resolution.)

SUSPICIOUS / INCONCLUSIVE (score 0.4-0.6, verdict 'Unusual_External_DNS'):
- DNS to an UNRECOGNISED IP that is not a known resolver, but low volume and no tunneling signature — could be a one-off misconfig, could be early recon. Not enough to keep an analyst busy; auto-closes.

REAL THREAT — KEEP OPEN (score 0.7-0.9, verdict 'DNS_Tunneling_or_Rogue_DNS'):
- DNS tunneling signature: abnormally large bytes-per-query (Bytes_Sent/Bytes_Received far above the few-hundred-byte norm), very high sustained query counts to a single non-resolver IP, or one host fanning out DNS to MANY distinct non-resolver IPs (rotation).
- Rogue DNS: DNS to an arbitrary internal/external host that is clearly not a resolver (possible MITM/redirection), or a resolver on a known threat list.
- Treat a random workstation hitting a strange DNS far more suspiciously than a DC/forwarder hitting a public resolver.

CONFIRMED MALICIOUS (score 0.9-1.0, verdict 'DNS_Tunneling_or_Rogue_DNS'): clear, sustained high-volume tunneling pattern with large payloads — real data channel.

There is NO 'mitigated' band here (no block was applied). A benign FP keeps its low score and auto-closes; a real tunneling/rogue case keeps a high score and stays OPEN for the analyst.

VALID VERDICT STRINGS — emit exactly one of: 'Benign_Public_Resolver' | 'Unusual_External_DNS' | 'DNS_Tunneling_or_Rogue_DNS'

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence stating the decisive evidence). Do NOT default to a high score just because the offense fired — be highly skeptical; this rule's base rate is benign.
