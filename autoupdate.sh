#!/bin/bash

APP_DIR="/opt/qradar-middleware"
LOG_FILE="/opt/qradar-middleware/autoupdate.log"

cd $APP_DIR

# 1. Запитуємо у GitHub інформацію про стан гілки main (без завантаження самих файлів)
git fetch origin main > /dev/null 2>&1

# 2. Отримуємо хеші останніх коммітів (локального та на GitHub)
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{u})

# 3. Якщо хеші відрізняються, значить є новий код
if [ $LOCAL != $REMOTE ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - 🚀 Знайдено новий код на GitHub. Починаю оновлення..." >> $LOG_FILE
    
    # Завантажуємо зміни
    git pull origin main >> $LOG_FILE 2>&1
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - 🔄 Перезапуск служби qradar-middleware..." >> $LOG_FILE
    
    # Перезапускаємо Gunicorn / FastAPI
    systemctl restart qradar-middleware
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ✅ Оновлення успішно застосовано." >> $LOG_FILE
    echo "---------------------------------------------------" >> $LOG_FILE
fi