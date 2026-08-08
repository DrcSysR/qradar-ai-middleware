#!/bin/bash
#
# Миттєвий деплой на прод з робочої станції — щоб не чекати наступного тіку крона
# (крон ходить кожні 10 хв). Нічого не копіює: просто смикає той самий autoupdate.sh
# на mdlwr01, тобто шлях коду лишається один — git.
#
#   ./deploy.sh          # запушити поточний main і одразу розкотити
#   ./deploy.sh --no-push  # тільки розкотити те, що вже в origin/main
#
# Передумова: `ssh mdlwr01` працює (ключ у Bitwarden-агенті, сховище розблоковане).

set -u
HOST="${DEPLOY_HOST:-mdlwr01}"
APP_DIR="/opt/qradar-middleware"

if [ "${1:-}" != "--no-push" ]; then
    echo "▶ Смоук-тест локально..."
    python3 tests/smoke_test.py || { echo "✋ Смоук-тест не пройдено — деплой скасовано."; exit 1; }

    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    if [ "$BRANCH" != "main" ]; then
        echo "✋ Ви на гілці '$BRANCH', а деплоїться лише main."; exit 1
    fi
    if [ -n "$(git status --porcelain)" ]; then
        echo "✋ Є незакомічені зміни — спершу коміт."; git status --short; exit 1
    fi
    echo "▶ git push origin main..."
    git push origin main || exit 1
fi

echo "▶ Запуск autoupdate.sh на $HOST..."
ssh -o ConnectTimeout=15 "$HOST" "$APP_DIR/autoupdate.sh"
RC=$?

echo "▶ Стан після деплою:"
ssh -o ConnectTimeout=15 "$HOST" "cd $APP_DIR && echo -n '   HEAD: ' && git rev-parse --short HEAD && \
    echo -n '   сервіс: ' && systemctl is-active qradar-middleware && \
    echo '   останні рядки логу:' && tail -4 $APP_DIR/autoupdate.log | sed 's/^/     /'"

# autoupdate.sh віддає 0 і коли оновлювати нічого — це не помилка
[ $RC -eq 0 ] && echo "✔ Готово." || echo "✖ autoupdate.sh завершився з кодом $RC — дивись лог вище."
exit $RC
