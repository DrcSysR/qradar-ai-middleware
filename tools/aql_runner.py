"""Універсальний раннер AQL. Токен бере з /opt/qradar-middleware/config.json.

Запуск з робочої станції:
    ssh mdlwr01 'python3 -' < tools/aql_runner.py <<< "SELECT ... LAST 24 HOURS"
Або на самому mdlwr01:
    python3 aql_runner.py <<< "SELECT ..."

AQL читається зі stdin. Порядок клауз важливий: LIMIT ставиться ПЕРЕД LAST,
а ORDER BY по кількох аліасах QRadar не приймає.
"""

import json, sys, time, requests, urllib3
urllib3.disable_warnings()

cfg = json.load(open('/opt/qradar-middleware/config.json'))
base = cfg['qradar_url'].rstrip('/')
h = {'SEC': cfg['qradar_token'], 'Version': '12.0', 'Accept': 'application/json'}
aql = sys.argv[1]

r = requests.post(base + '/api/ariel/searches', headers=h, params={'query_expression': aql}, verify=False)
if r.status_code >= 400:
    print('SUBMIT', r.status_code, r.text[:500])
    sys.exit(1)
sid = r.json()['search_id']
st = None
for _ in range(300):
    s = requests.get(base + '/api/ariel/searches/' + sid, headers=h, verify=False).json()
    st = s.get('status')
    if st in ('COMPLETED', 'ERROR', 'CANCELED'):
        break
    time.sleep(2)
if st != 'COMPLETED':
    print('STATUS', st, s.get('error_messages'))
    sys.exit(1)
res = requests.get(base + '/api/ariel/searches/' + sid + '/results', headers=h,
                   params={'Range': 'items=0-299'}, verify=False).json()
rows = res.get('events', [])
print('rows:', len(rows))
for row in rows:
    print(' | '.join('%s=%s' % (k, v) for k, v in row.items()))
