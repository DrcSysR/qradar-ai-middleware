# CLAUDE.md

## Git authorization

SSH до GitHub налаштовано (`origin` = `git@github.com:DrcSysR/qradar-ai-middleware.git`).
Після правки коду Claude може самостійно робити `git commit` і `git push origin <branch>` без додаткового підтвердження.

Винятки — як завжди питати перед виконанням:
- `git push --force` / `--force-with-lease`
- `git reset --hard`, `git clean -f`, видалення гілок
- `git rebase` / `git commit --amend` на вже запушених комітах
- комміт файлів які виглядають як секрети (`config.json`, `*.pem`, токени) — у цьому репо `*.json` у `.gitignore` крім `prompts.json`, тримати так

Деплой: пуш у `origin/main` → `autoupdate.sh` на проді сам зробить `git pull` і `systemctl restart qradar-middleware`. Тобто кожен пуш у main = реліз. Пушити обережно.
