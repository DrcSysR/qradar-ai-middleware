REMINDER: This SIEM rule (UC-03-1) fires on FEED MEMBERSHIP ONLY and is HEAVILY susceptible to False Positives.

Prompt: Analyze traffic between an internal host and an external IP that appears in an IBM X-Force "Risky IP" threat feed (categories such as Spam, Scanning, Anonymisation, Malware).

CRITICAL CONTEXT — read before scoring:
The offense is indexed by the EXTERNAL IP (it is the destination); the internal asset
under review is the `Internal_Host` column. `IOC_Category` tells you WHICH feed flagged
the address — a "Spam" listing is vastly weaker evidence than "Malware" or "Botnet C&C".
Mere feed membership is NOT evidence of compromise: these feeds are polluted with
shared-infrastructure fronts, residential/consumer addresses and P2P swarm peers. The
well-known benign CDN/SaaS ranges (Cloudflare, Apple, Meta, Google, Fastly, public DNS)
are ALREADY filtered out of the events below. Score on OBSERVED BEHAVIOUR — App,
Category, Port, byte volumes, periodicity — never on the bare fact that the rule fired.

**FIRST CHECK — IS THIS A P2P SWARM PEER? Do this before anything else.**
If `App` is `bittorrent`, `bittorrent-*`, or any `unknown-p2p`/torrent-like application:
a BitTorrent client contacts hundreds of arbitrary peers, and a large share of any swarm
sits on consumer or compromised hosts that these feeds list generically. The IOC hit
carries NO information about compromise in that case. Emit `score: 0.3`,
`verdict: "P2P_Policy_Violation"` and name the host — this is an ACCEPTABLE-USE problem
(unauthorised P2P software, bandwidth, legal exposure), not an intrusion. Do NOT emit a
C2 verdict for swarm traffic, and do NOT escalate it as compromise.

**SECOND CHECK — is this expected inbound mail?**
If `Internal_Host` is a mail server and the port is SMTP (25 / 465 / 587) while
`IOC_Category` is Spam-related, then a spam-listed sender talking to our mail server is
the SYSTEM WORKING AS INTENDED — spam arrives from spam sources. Emit `score: 0.1`,
`verdict: "Expected_Inbound_Mail"`.

Verdict Benign_Feed_FalsePositive (score 0.2): `App` is a normal browser/web app
('web-browsing', 'ssl', 'tls', 'quic', 'http2', a named SaaS/update service), `Port` is
standard (80/443), `Category` is a real benign content category, and volumes look like
browsing. A legitimate site that merely shares an address the feed flagged generically.

Verdict Suspicious_Uncategorized_Egress (score 0.5): generic VPS / cloud-hosting IP
(DigitalOcean, OVH, Hetzner, AWS/Azure raw instances) over 'ssl'/'web-browsing' to an
uncategorized or low-reputation destination — anomalous, but no hard C2 proof.

Verdict Active_C2_Beaconing (score 0.95): CRITICAL, needs a human. Any of: `App` is
'unknown-tcp'/'unknown-udp'; raw IP with no web category; non-standard high port that is
not P2P; or small fixed-size periodic beacons. Note the exclusion — 'unknown-p2p' with a
torrent profile belongs to FIRST CHECK, not here.

Be decisive: a feed-only false positive that is plainly normal browsing MUST score <=0.4
so the offense auto-closes. Reserve 0.95 for genuine C2 signal in the traffic shape, and
remember that a score above 0.6 keeps the offense OPEN for an analyst.

OUTPUT: respond with ONLY a single JSON object, no other text:
{"score": <float 0.0-1.0>, "verdict": "<one of the verdict strings above>", "explanation": "<one sentence, max 15 words>"}
