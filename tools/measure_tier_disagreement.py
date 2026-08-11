"""ВИМІРЮВАННЯ (тільки читання): чи згоден Vertex із вердиктами tier-1 у смузі 0.4-0.6.

НІЧОГО НЕ ЗМІНЮЄ: не пише нотаток, не закриває офенси, не чіпає refset і не торкається
ai_state.db на запис. Тільки читає QRadar, ганяє AQL і питає Vertex.

Логіка повторює app.py: той самий AQL-шаблон із prompts.json, той самий текст промпту,
але вікно 168 год (як у tier-2) замість 4 год у tier-1.
"""
import json, sys, time, glob, sqlite3, datetime
import requests, urllib3
from google.oauth2 import service_account
import google.auth.transport.requests

sys.path.insert(0, "/opt/qradar-middleware")
from prompts_loader import get_dynamic_prompt

urllib3.disable_warnings()
CFG = json.load(open("/opt/qradar-middleware/config.json"))
BASE = CFG["qradar_url"].rstrip("/")
H = {"SEC": CFG["qradar_token"], "Version": "12.0", "Accept": "application/json"}
PROMPTS_FILE = "/opt/qradar-middleware/prompts.json"
PROMPTS_DIR = "/opt/qradar-middleware/prompts"
QUERIES_DIR = "/opt/qradar-middleware/queries"
WINDOW_MS = int(float(CFG.get("escalate_window_hours", 168)) * 3600 * 1000)
LIMIT = CFG.get("aql_limit", 1500)
MODEL = CFG.get("vertex_deep", "gemini-3-flash-preview")
PROJ = CFG.get("vertex_project")
LOC = CFG.get("vertex_location", "global")
SAMPLE = int(sys.argv[1]) if len(sys.argv) > 1 else 30

key = glob.glob("/opt/qradar-middleware/*vertex*.json")[0]
CREDS = service_account.Credentials.from_service_account_file(
    key, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def token():
    if not CREDS.valid:
        CREDS.refresh(google.auth.transport.requests.Request())
    return CREDS.token


def offense(oid):
    r = requests.get(f"{BASE}/api/siem/offenses/{oid}", headers=H, verify=False, timeout=60)
    return r.json() if r.status_code == 200 else None


def rules_map():
    r = requests.get(f"{BASE}/api/analytics/rules", headers=H, verify=False,
                     timeout=120, params={"fields": "id,name"})
    return {x["id"]: x.get("name", "") for x in r.json()} if r.status_code == 200 else {}


def run_aql(aql, timeout_s=300):
    r = requests.post(f"{BASE}/api/ariel/searches", headers=H, verify=False,
                      params={"query_expression": aql}, timeout=60)
    if r.status_code >= 400:
        return None
    sid = r.json()["search_id"]
    for _ in range(timeout_s // 2):
        s = requests.get(f"{BASE}/api/ariel/searches/{sid}", headers=H, verify=False, timeout=60).json()
        if s.get("status") in ("COMPLETED", "ERROR", "CANCELED"):
            break
        time.sleep(2)
    if s.get("status") != "COMPLETED":
        return None
    res = requests.get(f"{BASE}/api/ariel/searches/{sid}/results", headers=H, verify=False,
                       params={"Range": f"items=0-{LIMIT-1}"}, timeout=180).json()
    return res.get("events", [])


PROMPT_TAIL = (
    "Based ONLY on the logs above, return a valid JSON object with keys "
    "'score', 'verdict', 'explanation', and optionally 'mitigated'.\n\n"
    "CRITICAL RULES FOR JSON:\n"
    "1. 'score' must be a float between 0.0 and 1.0 based on the rubric below.\n"
    "2. 'verdict' must be a short category string.\n"
    "3. 'explanation' MUST BE EXTREMELY CONCISE. Strictly 1 short sentence, maximum 15 words.\n"
    "4. 'mitigated' (boolean, default false): set TRUE for a real/suspicious action that was FULLY BLOCKED, "
    "DENIED, DROPPED or FAILED with NO successful outcome and no sign of an already-compromised internal asset.\n\n"
    "CRITICAL SCORING RUBRIC for 'score' (float 0.0 to 1.0):\n"
    "- 0.0 to 0.3: CLEAR FALSE POSITIVE.\n"
    "- 0.4 to 0.6: SUSPICIOUS BUT INCONCLUSIVE.\n"
    "- 0.7 to 0.8: HIGHLY SUSPICIOUS with a REAL, UN-BLOCKED consequence.\n"
    "- 0.9 to 1.0: CONFIRMED COMPROMISE.\n\n"
    "ANTI-DEFAULT RULE: a score of 0.7+ pages a human analyst. Do NOT pick 0.7-0.8 because you are uncertain — "
    "uncertainty WITHOUT a concrete un-blocked consequence is the 0.4-0.6 band, or, if the threat was "
    "contained, mitigated:true.\n\n"
    "Do NOT default to a high score just because an offense was triggered. Be highly skeptical. "
    "Output ONLY the JSON object."
)


def ask_vertex(prompt):
    host = "aiplatform.googleapis.com" if LOC == "global" else f"{LOC}-aiplatform.googleapis.com"
    url = (f"https://{host}/v1/projects/{PROJ}/locations/{LOC}"
           f"/publishers/google/models/{MODEL}:generateContent")
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 4096,
                                 "responseMimeType": "application/json"}}
    r = requests.post(url, headers={"Authorization": f"Bearer {token()}"}, json=body, timeout=240)
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}: {r.text[:120]}"
    try:
        cand = r.json()["candidates"][0]
        txt = cand["content"]["parts"][0]["text"]
    except Exception as e:
        return None, "структура відповіді: %s | %s" % (str(e)[:40], json.dumps(r.json())[:160])
    try:
        return json.loads(txt), None
    except Exception:
        pass
    # запасний парсер, як в app.py: витягнути перший обʼєкт зі score
    import re
    m = re.search(r'\{[^{}]*"score"[^{}]*\}', txt, re.S)
    if m:
        try:
            return json.loads(m.group(0)), None
        except Exception:
            pass
    return None, "не JSON (finish=%s): %r" % (cand.get("finishReason"), txt[:120])


db = sqlite3.connect("/opt/qradar-middleware/ai_state.db")
rows = list(db.execute("""
    select offense_id, score, verdict from offenses
    where score > 0.35 and score <= 0.6 and last_updated > datetime('now','-2 days')
    order by last_updated desc limit ?""", (SAMPLE,)))
print(f"вибірка: {len(rows)} офенсів зі смуги 0.4-0.6 за 2 доби")
print(f"tier-2: {MODEL}, вікно {WINDOW_MS//3600000} год, ліміт AQL {LIMIT}\n")
rm = rules_map()

agree = disagree_up = disagree_down = failed = 0
results = []
for i, (oid, t1_score, t1_verdict) in enumerate(rows, 1):
    d = offense(oid)
    if not d:
        print(f"[{i}/{len(rows)}] {oid}: офенс недоступний"); failed += 1; continue
    names = [rm.get(r.get("id"), "") for r in d.get("rules", [])]
    instruction, _assignee, aql_file, _rc, _coe = get_dynamic_prompt(
        d.get("offense_name", ""), PROMPTS_FILE, PROMPTS_DIR, rule_names=names)

    start = d.get("start_time"); end = d.get("last_updated_time") or start
    depth = (f"START {int(start)-WINDOW_MS} STOP {int(end)+300000}" if start else "LAST 168 HOURS")
    try:
        tpl = open(f"{QUERIES_DIR}/{aql_file}", encoding="utf-8").read()
    except Exception:
        tpl = ("SELECT * FROM events WHERE INOFFENSE({offense_id}) "
               "ORDER BY starttime DESC LIMIT {limit} {time_depth}")
    ev_val = str(d.get("entity_value", "") or "")
    ev_type = d.get("entity_type", "") or ""
    aql = tpl.format(offense_id=oid, time_depth=depth, limit=LIMIT,
                     source_ip=ev_val if ev_type in ("SourceIP", "DestinationIP") else "",
                     username=ev_val if ev_type == "User" else "")
    events = run_aql(aql)
    n_ev = len(events) if events else 0

    prompt = ("You are an expert Tier-2 SOC analyst. "
              f"Context: QRadar triggered an offense named '{d.get('offense_name','')}'. "
              "SIEM rules often generate False Positives. Your primary job is to act as a filter.\n\n"
              f"Task: {instruction}\n\n"
              f"--- START OF LOGS ---\n{str(events)[:2000000]}\n--- END OF LOGS ---\n\n"
              + PROMPT_TAIL)
    v, err = ask_vertex(prompt)
    if v is None:
        print(f"[{i}/{len(rows)}] {oid}: Vertex помилка {err}"); failed += 1; continue
    t2 = float(v.get("score", -1))
    delta = t2 - t1_score
    tag = "=" if abs(delta) < 0.15 else ("⚠ ВИЩЕ" if delta > 0 else "нижче")
    if t2 > 0.6:
        disagree_up += 1
    elif abs(delta) < 0.15:
        agree += 1
    else:
        disagree_down += 1
    results.append((oid, t1_score, t2, n_ev, v.get("verdict", "")[:28]))
    print(f"[{i}/{len(rows)}] {oid}: tier1={t1_score} -> tier2={t2} {tag:8} "
          f"подій(168год)={n_ev:<5} {v.get('verdict','')[:32]}")
    sys.stdout.flush()

n = len(results)
print("\n" + "=" * 72)
print(f"проаналізовано {n}, помилок {failed}")
if n:
    print(f"  Vertex підняв ВИЩЕ 0.6 (мали б піти аналітику): {disagree_up}  ({100.0*disagree_up/n:.0f}%)")
    print(f"  згода (різниця < 0.15):                         {agree}  ({100.0*agree/n:.0f}%)")
    print(f"  Vertex оцінив помітно нижче:                    {disagree_down}  ({100.0*disagree_down/n:.0f}%)")
    ups = [r for r in results if r[2] > 0.6]
    if ups:
        print("\n  Офенси, які tier-1 закрив, а Vertex вважає вартими уваги:")
        for oid, s1, s2, ne, vd in sorted(ups, key=lambda x: -x[2]):
            print(f"    {oid}  {s1} -> {s2}  подій={ne}  {vd}")
