#!/bin/bash
#
# Автооновлення прода: git pull → залежності → смоук-тест → рестарт → health-check.
# Запускається з крона на mdlwr01. Реліз = пуш у origin/main.
#
# Що змінилось 2026-08-08:
#  * вивід git більше не сиплеться в лог щоцикл (лог розрісся до 469K і в ньому
#    неможливо було знайти реальні події) — пишемо тільки при помилці;
#  * якщо в коміті змінився requirements.txt, ставимо залежності ДО рестарту,
#    інакше нова залежність кладе сервіс і ми відкочуємось без причини;
#  * перед рестартом ганяємо tests/smoke_test.py — зламаний prompts.json або .aql
#    із кривим плейсхолдером далі не проходить;
#  * лог підрізається, щоб не ріс безмежно.
#
# Ручний запуск (миттєвий деплой замість очікування крона): ./deploy.sh з робочої станції.

APP_DIR="/opt/qradar-middleware"
LOG_FILE="$APP_DIR/autoupdate.log"
SERVICE="qradar-middleware"
HEALTH_URL="http://127.0.0.1:5000/"
HEALTH_TIMEOUT=10
HEALTH_RETRIES=6
VENV_PIP="$APP_DIR/venv/bin/pip"
LOG_MAX_LINES=3000

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Підрізаємо лог на старті, а не в кінці: інакше при exit 1 він ніколи не підрізається.
if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE")" -gt "$LOG_MAX_LINES" ]; then
    tail -n "$LOG_MAX_LINES" "$LOG_FILE" > "$LOG_FILE.tmp" && mv -f "$LOG_FILE.tmp" "$LOG_FILE"
fi

cd "$APP_DIR" || { log "❌ Не можу зайти в $APP_DIR"; exit 1; }

# 1. Fetch. Вивід тримаємо в змінній і пишемо в лог ЛИШЕ якщо щось пішло не так.
FETCH_OUT=$(git fetch origin main 2>&1)
if [ $? -ne 0 ]; then
    log "⚠️ git fetch впав (мережа? GitHub? ключ?). Пропуск циклу."
    log "   $FETCH_OUT"
    exit 1
fi

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse '@{u}')

# 2. Немає нового коду — тихо виходимо
[ "$LOCAL" = "$REMOTE" ] && exit 0

log "🚀 Знайдено новий код ($(echo "$LOCAL" | cut -c1-8) → $(echo "$REMOTE" | cut -c1-8)). Оновлення..."
PREV_SHA="$LOCAL"

# 3. Чи змінюється requirements.txt у цьому оновленні — вирішуємо ДО pull
REQ_CHANGED=0
if ! git diff --quiet "$LOCAL" "$REMOTE" -- requirements.txt 2>/dev/null; then
    REQ_CHANGED=1
fi

# 4. Pull
if ! git pull --ff-only origin main >> "$LOG_FILE" 2>&1; then
    log "❌ git pull впав (локальні зміни / конфлікт). Сервіс НЕ перезапускається."
    exit 1
fi

# 5. Залежності — тільки якщо requirements.txt справді змінився
if [ "$REQ_CHANGED" -eq 1 ] && [ -x "$VENV_PIP" ] && [ -f requirements.txt ]; then
    log "📦 requirements.txt змінився — оновлюю залежності у venv..."
    if ! "$VENV_PIP" install -q -r requirements.txt >> "$LOG_FILE" 2>&1; then
        log "❌ pip install впав. Відкат на $PREV_SHA, сервіс не чіпаємо."
        git reset --hard "$PREV_SHA" >> "$LOG_FILE" 2>&1
        exit 1
    fi
fi

# 6. Смоук-тест ДО рестарту: зламаний prompts.json / .aql далі не пускаємо.
#    Тест лише на stdlib, QRadar не потрібен.
if [ -f tests/smoke_test.py ]; then
    SMOKE_OUT=$(python3 tests/smoke_test.py 2>&1)
    if [ $? -ne 0 ]; then
        log "❌ Смоук-тест не пройдено — відкат на $PREV_SHA, сервіс НЕ перезапускається."
        echo "$SMOKE_OUT" | grep -E "FAIL|підсумок" >> "$LOG_FILE"
        git reset --hard "$PREV_SHA" >> "$LOG_FILE" 2>&1
        exit 1
    fi
fi

# 7. Рестарт
log "🔄 Перезапуск $SERVICE..."
systemctl restart "$SERVICE"

# 8. Health-check
sleep 3
HEALTHY=0
for i in $(seq 1 "$HEALTH_RETRIES"); do
    if curl -sf --max-time "$HEALTH_TIMEOUT" "$HEALTH_URL" > /dev/null; then
        HEALTHY=1
        break
    fi
    sleep 5
done

if [ "$HEALTHY" -eq 1 ]; then
    log "✅ Оновлено до $(git rev-parse --short HEAD). Сервіс відповідає."
    log "---------------------------------------------------"
    exit 0
fi

# 9. Відкат
log "🔥 Сервіс НЕ відповідає. Відкат на $PREV_SHA..."
git reset --hard "$PREV_SHA" >> "$LOG_FILE" 2>&1
if [ "$REQ_CHANGED" -eq 1 ] && [ -x "$VENV_PIP" ] && [ -f requirements.txt ]; then
    "$VENV_PIP" install -q -r requirements.txt >> "$LOG_FILE" 2>&1
fi
systemctl restart "$SERVICE"
sleep 3
if curl -sf --max-time "$HEALTH_TIMEOUT" "$HEALTH_URL" > /dev/null; then
    log "↩️  Відкат успішний. Сервіс знову відповідає."
else
    log "💀 Відкат не допоміг. Потрібне ручне втручання!"
fi
log "---------------------------------------------------"
exit 1
