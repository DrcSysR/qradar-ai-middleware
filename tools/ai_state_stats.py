"""Статистика вердиктів з ai_state.db: скор-банди по днях, ескалації, останні записи.

    ssh mdlwr01 'python3 -' < tools/ai_state_stats.py

sqlite3 на mdlwr01 НЕ встановлений — тому саме python3 і саме через stdin
(вкладені лапки в ssh-героку ламаються).
"""

import sqlite3
c = sqlite3.connect("/opt/qradar-middleware/ai_state.db")

print("=== скор-банди по днях (14 діб):")
print("   день        null  0-0.3  0.4-0.6  0.7-0.8  0.9-1.0  всього")
for r in c.execute("""
select date(last_updated) d,
  sum(case when score is null then 1 else 0 end),
  sum(case when score<=0.3 then 1 else 0 end),
  sum(case when score>0.3 and score<=0.6 then 1 else 0 end),
  sum(case when score>0.6 and score<=0.8 then 1 else 0 end),
  sum(case when score>0.8 then 1 else 0 end),
  count(*)
from offenses where last_updated > datetime('now','-14 days')
group by d order by d"""):
    print("   %s  %5s %6s %8s %8s %8s %7s" % r)

print("\n=== усі офенси зі score > 0.6 за 14 діб:")
rows = list(c.execute("""
select offense_id, score, substr(coalesce(verdict,''),1,40), coalesce(escalated,-1), last_updated
from offenses where score > 0.6 and last_updated > datetime('now','-14 days')
order by last_updated desc limit 15"""))
if rows:
    for r in rows:
        print("   ", " | ".join(str(x) for x in r))
else:
    print("   ЖОДНОГО — нічого не дійшло до аналітика за 14 діб")

print("\n=== топ вердиктів за 7 діб:")
for r in c.execute("""
select coalesce(nullif(verdict,''),'<порожній>') v, count(*), round(avg(score),2)
from offenses where last_updated > datetime('now','-7 days') and score is not null
group by v order by 2 desc limit 12"""):
    print("   %-45s %5s  avg=%s" % r)

print("\n=== ескалації (tier-2) за 14 діб:")
for r in c.execute("""
select coalesce(escalated,-1) esc, count(*) from offenses
where last_updated > datetime('now','-14 days') group by esc"""):
    print("   escalated=%s : %s" % r)
