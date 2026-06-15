REMINDER: This SIEM rule (UC-02-1) is HEAVILY susceptible to False Positives.

Prompt: Analyze outbound connections from an internal host to external IPs that appear in the IBM X-Force "Botnet C&C IPs" reference set.

CRITICAL CONTEXT — read before scoring:
The offense fired ONLY because the destination IP is listed in a large (~101k) X-Force
threat feed. That feed is polluted with SHARED-INFRASTRUCTURE front IPs (CDN / cloud
reverse-proxies) behind which millions of legitimate sites live. Mere membership in the
feed is therefore NOT evidence of compromise. The well-known benign CDN/SaaS ranges
(Cloudflare, Apple, Meta, Google, Fastly, public DNS resolvers) have already been
filtered out of the events below; what remains are the destinations that still deserve
judgement. Score on the OBSERVED BEHAVIOUR (application, web category, port, volume,
periodicity), never on the bare fact that the rule fired.

FIRST CHECK — is this just normal web traffic to a flagged front?
1. Is the 'App' a normal browser/web app ('web-browsing', 'ssl', 'tls', 'quic',
   'http2', a named SaaS like 'ms-update', 'apple-update') AND
2. Is the 'Category' a real, benign content category (business, news, CDN,
   technology, web-advertisements, content-delivery, …) AND
3. Is the 'Port' standard (80 / 443) AND volumes look like browsing (not tiny,
   fixed-size, periodic beacons)?
If ALL hold → this is a feed false-positive. Verdict Benign, score 0.2.

Verdict Benign (Score 0.2): Categorized, reputable destination over standard HTTP/TLS
with normal browsing volumes — a legitimate site that merely shares a hosting/CDN IP
the X-Force feed flagged generically.

Verdict Suspicious (Score 0.5): Generic VPS / cloud-hosting IP (e.g. DigitalOcean,
hetzner, OVH, bulletproof-hosting ranges) with 'ssl'/'web-browsing' to an
uncategorized or low-reputation site — anomalous for this user but no hard C2 proof.

Verdict Active_C2_Beaconing (Score 0.95+): CRITICAL. Any of: 'App' is
'unknown-tcp'/'unknown-udp'/'unknown-p2p'; raw IP with NO web category / 'uncategorized';
non-standard high port; or small fixed-size, periodic beacons. This is a confirmed C2
candidate — escalate to a human, do NOT auto-close.

Be decisive: a feed-only false-positive that is plainly normal browsing MUST score ≤0.4
so it auto-closes; reserve 0.95 for genuine C2 signal in the traffic shape.

OUTPUT: respond with ONLY a single JSON object, no other text:
{"score": <float 0.0-1.0>, "verdict": "<one of the verdict strings above>", "explanation": "<one sentence, max 15 words>"}
