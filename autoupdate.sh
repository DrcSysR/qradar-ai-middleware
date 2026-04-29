#!/bin/bash

APP_DIR="/opt/qradar-middleware"
LOG_FILE="/opt/qradar-middleware/autoupdate.log"
SERVICE="qradar-middleware"
HEALTH_URL="http://127.0.0.1:5000/"
HEALTH_TIMEOUT=10
HEALTH_RETRIES=6

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

cd "$APP_DIR" || { log "❌ Не можу зайти в $APP_DIR"; exit 1; }

# 1. Перевіряємо стан репозиторію (мережа + git)
if ! git fetch origin main 2>>"$LOG_FILE"; then
    log "⚠️ git fetch впав (мережа? GitHub? авторизація?). Пропуск циклу."
    exit 1
fi

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse '@{u}')

# 2. Якщо хеші відрізняються, значить є новий код
if [ "$LOCAL" = "$REMOTE" ]; then
    exit 0
fi

log "🚀 Знайдено новий код на GitHub ($LOCAL → $REMOTE). Починаю оновлення..."

# 3. Зберігаємо попередній SHA для можливого rollback
PREV_SHA="$LOCAL"

# 4. Pull
if ! git pull --ff-only origin main >> "$LOG_FILE" 2>&1; then
    log "❌ git pull впав (можливі локальні зміни / merge conflict). Сервіс НЕ перезапускається."
    exit 1
fi

# 5. Restart
log "🔄 Перезапуск служби $SERVICE..."
systemctl restart "$SERVICE"

# 6. Health-check: чекаємо, поки сервіс підніметься
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
    log "✅ Оновлення успішно застосовано. Сервіс відповідає."
    log "---------------------------------------------------"
else
    log "🔥 Сервіс НЕ відповідає після оновлення. Виконую rollback на $PREV_SHA..."
    git reset --hard "$PREV_SHA" >> "$LOG_FILE" 2>&1
    systemctl restart "$SERVICE"
    sleep 3
    if curl -sf --max-time "$HEALTH_TIMEOUT" "$HEALTH_URL" > /dev/null; then
        log "↩️  Rollback успішний. Сервіс знову відповідає."
    else
        log "💀 Rollback теж не допоміг. Потрібне ручне втручання!"
    fi
    log "---------------------------------------------------"
    exit 1
fi
