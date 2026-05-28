CONTEXT: Offense triggered by the QRadar rule "Excessive Firewall Denies Between Hosts" (also "UC-ME Excessive Firewall Denies Between Hosts R2L Action Block"). The offense fires when a single source IP generates many firewall/ACL deny events toward a single destination IP within a short window. NO chained sub-rule fired (no Powershell, no thread injection, no beaconing) — this is the plain deny-burst case. The offense.description embedded in the framing line above tells you WHICH variant fired (Reset Both / Session Denied / Traffic End / Failure Audit: Windows Filtering Platform / SSH login fail / R2L Action Block). Read it.

CORPORATE NETWORK MAP — use this to classify each src/dst:
- TRUSTED INTERNAL: 172.17.0.0/16, 192.168.48.0/21, 172.20.22.0/23 (VPN), 172.17.200.0/23 (remote DC)
- CAMERAS (Hikvision, very noisy multicast): 192.168.100.0/24
- GUEST / UNTRUSTED INTERNAL (treat like external): all other RFC1918, e.g. 172.19.0.0/16, undocumented 10.x.x.x, undocumented 192.168.x.x
- LINK-LOCAL / MULTICAST (always noise): IPv4 169.254.0.0/16, IPv4 multicast 224.0.0.0/4 (incl. 224.0.0.251 mDNS), IPv6 fe80::/10 (link-local), IPv6 ff00::/8 (multicast incl. ff02::fb mDNS, ff02::1:2 DHCPv6, ff02::1:3 LLMNR)
- EXTERNAL: public unicast IPv4/IPv6

INPUT SHAPE: Raw firewall deny events (Palo Alto / WFP / pfSense). Columns include Time, LogSource, EventName (QID), Category, sourceip, destinationip, destinationport, Action, payload. There is no Sysmon correlation in this AQL — work from the firewall data alone.

HARD SCORING ANCHORS — apply BEFORE general reasoning. Lowest applicable anchor wins.

ANCHOR 1 — MUST score ≤ 0.2, verdict 'Multicast/LinkLocal_Noise':
- Destination IP is in IPv4 multicast 224.0.0.0/4 OR IPv6 multicast ff00::/8 OR IPv4 169.254.0.0/16 OR IPv6 link-local fe80::/10
- OR Source IP is in any of those ranges
- OR src/dst is in 192.168.100.0/24 (Hikvision cameras) and the denied port is 1900 (SSDP), 5353 (mDNS), 3702 (WS-Discovery), 5355 (LLMNR), 137-139, or 67-68 (DHCP)
- **OR the MAJORITY (≥40%) of events have destination in IPv4/IPv6 multicast OR link-local OR use a discovery port (5353/1900/3702/5355/137-139)** — the rule fired on discovery noise from the source device; the minority of unicast events is normal companion traffic from the same device (web/CDN/push) and does NOT change the verdict.
- **BYOD carve-out:** if source is GUEST RFC1918 (e.g. 172.18.x.x, 172.19.x.x) AND ≥40% of events are multicast/discovery ports above AND the unicast destinations look like public CDN/SaaS (Apple 17.x.x.x, Google 8.8.x.x, Fastly 151.101.x.x, etc.) with NO service-port (445/3389/22/...) hitting trusted-internal — this is a mobile/IoT device on guest net doing normal discovery + internet, not lateral recon. Score 0.0–0.2.
- This is mDNS / SSDP / LLMNR / camera-discovery noise. Always FP. The "potential C2" framing does NOT apply.

ANCHOR 2 — MUST score ≤ 0.3, verdict 'LAN_To_LAN_Misconfig':
- BOTH src and dst are in TRUSTED INTERNAL ranges (172.17.0.0/16, 192.168.48.0/21, 172.20.22.0/23, 172.17.200.0/23)
- AND Action is Block / Drop / Deny / "Session Denied" / "Reset Both" / WFP Failure Audit
- AND there is no row in the events with Action=Allow/Accept for the same src→dst:port
- This is a misconfigured client retrying a service the dst doesn't allow (SMB to a non-server, RDP to a workstation, SQL to a host that moved, etc.). Almost always FP. Name the dst port in the explanation if it suggests the service.

ANCHOR 2B — MUST score ≤ 0.3, verdict 'Benign_App_Web_Fanout_Outbound' — FP, auto-close. **OVERRIDES ANCHOR 6 — check this FIRST.**
- **FIRST STEP — count the ports.** Source is TRUSTED INTERNAL, destinations are EXTERNAL or mixed.
- **Trigger when ALL of:**
  1. EVERY observed dst port is in the web/app/messaging/infra set `{80, 443, 8443, 53, 123, 853, 5222, 5223, 5228 (Google push), 5280, 5353 (mDNS), 5005 (RTP), 4244 (Viber chat), 3544 (Teredo), 7000, 8001-8010 (app/Tomcat-like)}`; AND
  2. NONE of the service/admin ports `{445, 3389, 22, 5985, 135, 1433, 3306, 5432, 161, 5900, 23, 593}` appears EVEN ONCE; AND
  3. Multiple distinct dst hosts (>5) — it's a fan-out shape, not a single-target burst.
- This is normal outbound from a workstation/server reaching many SaaS/CDN/push/messaging endpoints that egress filtering blocked. NOT a beacon (a beacon is ONE fixed external IP on ONE port — ANCHOR 6). Host count is irrelevant when the port set is purely web/app/messaging.
- Do NOT apply ANCHOR 6 if the fan-out spans many different dst IPs OR the port set is purely web/app.

ANCHOR 3 — MUST score ≤ 0.3, verdict 'PA_R2L_Block_Already_Mitigated':
- offense.description contains "R2L Action Block" OR Action=Block consistently AND Source IP is EXTERNAL (public unicast) AND Destination IP is TRUSTED INTERNAL
- AND there is no Allow row for the same src→dst:port in the window
- Palo Alto already blocked it — this is the firewall doing its job catching an external scan. Note the dst port; if it's RDP/SMB/SSH/HTTP-mgmt/IMPI exposed to the internet, raise the issue separately to network team but DO NOT score as compromise.

ANCHOR 4 — score 0.7–0.8, verdict 'External_Scan_Blocked' — set "mitigated": true (recognized + contained, auto-closes):
- Source IP is EXTERNAL AND sustained deny burst (event_count high, multiple distinct dst hosts in the same offense, or multiple distinct dst ports = port-scan shape)
- AND no Allow row from this source (every event is a deny/block)
- This is a recognized external scan/probe that the firewall FULLY BLOCKED — malicious in intent but contained, no internal asset implicated, no consequence. Set "mitigated": true so the offense closes (the radar's own escalating PA action / botnet_scan handle the IP). Keep the honest high score. Do NOT route to an analyst just because the source is external — the block already did its job.

ANCHOR 5 — score 0.6–0.8, verdict 'Guest_To_Internal_Probing' — leave open. **REQUIRES the source IP to be in a GUEST / untrusted-internal RFC1918 range (e.g. 172.19.x.x); a public-unicast EXTERNAL source is NEVER this anchor — that is ANCHOR 4.**
- Source IP is in GUEST / UNTRUSTED INTERNAL (RFC1918 outside the trusted ranges, e.g. 172.19.x.x, undocumented 10.x.x.x) AND destination is TRUSTED INTERNAL
- AND burst hits multiple internal hosts OR multiple ports (lateral-scan shape)
- This is the most dangerous shape in this rule: a device on guest/BYOD network probing corporate LAN. Even if blocked, escalate to analyst — possibly compromised guest device or rogue contractor laptop.

ANCHOR 6 — score 0.7–0.9, verdict 'Internal_Outbound_Burst' — leave open. **REQUIRES all of: (a) ONE single fixed external dst IP, (b) ONE single non-standard port, (c) repeated denies to that exact dst_ip:dst_port. If destinations span many IPs OR the port is 80/443/53/853, this is ANCHOR 2B (benign fan-out), NOT a beacon.**
- Source IP is TRUSTED INTERNAL AND destination is EXTERNAL AND repeated denies to the SAME external IP
- AND the dst port is non-standard (>1024, not 80/443/53/853)
- Internal host attempting blocked outbound to a fixed external endpoint = candidate beacon. Escalate.

ANCHOR 7 — score 0.4, verdict 'SSH_Bruteforce_Already_Blocked':
- offense.description contains "User failed to login to SSH"
- AND the failed-SSH events also appear in the deny events for the same src
- Already covered by the SSH bruteforce rule; this composite is duplicate noise. Score moderate, do not auto-close in case SSH rule itself missed.

ANCHOR 8 — score ≤ 0.3, verdict 'Blocked_No_Other_Violations' — auto-close:
- If no other security violations, active compromises, or credential anomalies are detected, and the suspicious activity is fully blocked/denied by the firewall (with no successful 'Allow' events), it is considered contained and safe to close (score ≤ 0.3).

MITIGATED — RECOGNIZED MALICIOUS BUT FULLY BLOCKED (set "mitigated": true; offense auto-closes):
- Core rule for this offense type: when the deny burst is a recognized malicious/suspicious pattern (external scan, port-sweep, probe) that the firewall FULLY BLOCKED — every event a deny, NO Allow row for the same src→dst:port — AND no internal asset is implicated as the cause, set "mitigated": true with the honest score. The threat was recognized and contained; close it, don't bother the analyst. This is ANCHOR 3 and ANCHOR 4 (EXTERNAL source blocked).
- KEEP OPEN (mitigated:false), because an internal/guest device of OURS is implicated and may itself be compromised even though the traffic was blocked:
  - ANCHOR 5 (GUEST / untrusted-internal source probing the LAN) — the guest/BYOD device needs a look.
  - ANCHOR 6 (TRUSTED-INTERNAL source making blocked outbound to a fixed external endpoint = beacon candidate) — the internal host may be compromised; the block stops the channel but not the infection.
- Multicast/LAN-misconfig (ANCHOR 1, 2) stay as low-score FP and auto-close on score, no mitigated needed.

VALID VERDICT STRINGS for this prompt — use ONLY one of:
'Multicast/LinkLocal_Noise', 'LAN_To_LAN_Misconfig', 'Benign_App_Web_Fanout_Outbound', 'PA_R2L_Block_Already_Mitigated', 'External_Scan_Blocked', 'Guest_To_Internal_Probing', 'Internal_Outbound_Burst', 'SSH_Bruteforce_Already_Blocked', 'Blocked_No_Other_Violations', 'Inconclusive_FW_Burst'.
Do NOT emit verdicts from other prompts (e.g. 'Local_Host_Scanning_LAN', 'Local_Host_Scanning_Multiport', 'Highly Suspicious') — those belong to other rules.

FALLBACK: If none of the anchors fit, output score 0.5, verdict 'Inconclusive_FW_Burst' — let the analyst review.

EXPLANATION FIELD: max 15 words, one sentence. Name the dominant src/dst category and the dst port if known. Examples:
- "Hikvision camera mDNS to 224.0.0.251 — multicast noise"
- "LAN-to-LAN denies 172.17.55.10→172.17.55.40:445, dst not SMB server, misconfig"
- "External 185.x.x.x port-scan against 172.17.x range, PA blocked, no allow"
- "Guest 172.19.50.7 scanning 172.17.0.0/16 across ports 22/445/3389 — escalate"

Output ONLY a JSON object with keys 'score' (float), 'verdict' (one of the verdict strings above), 'explanation' (≤15 words), and optional 'mitigated' (boolean, default false — set true per ANCHOR 3/4 / the MITIGATED rule when an external malicious burst was fully blocked).
