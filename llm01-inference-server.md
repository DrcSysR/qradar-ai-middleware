# llm01 — локальний inference-сервер для middleware

> Створено 2026-08-05. Опис on-prem LLM-сервера, який планується використати як
> AI-провайдера для цього middleware (аналітика логів QRadar).
> **Головне попередження:** сервер зараз піднятий на **llama.cpp (OpenAI `/v1` API)**,
> а middleware у `app.py` говорить з **Ollama (`/api/generate`)**. Це різні API —
> див. розділ «Інтеграція», там два шляхи й рекомендація.

---

## 1. Ідентифікація та доступ

| Параметр | Значення |
|---|---|
| Hostname | `llm01.modern.org` |
| IP | `172.17.61.218` (VLAN 601) — **DHCP-оренда, не статика** |
| Гіпервізор | Proxmox `pve01`, VM ID **2101** (кластер MEG) |
| SSH | `ansible@172.17.61.218` |
| Ключ | виділений **ed25519**, `SHA256:NR+p06vEOhNUkMO8novjOuaJvOeUG2A4lfokC2Nn7ZI` |
| Ключ у Bitwarden | item `llm01.modern.org — ansible SSH (ed25519)` (тип SSH-key, працює через агент) |
| Запасний доступ | ключ кластера `id_rsa.pve` теж у `authorized_keys` |

```bash
ssh -i ~/.ssh/<llm01-key> ansible@172.17.61.218        # або через Bitwarden SSH-агент
```

> ⚠️ **DHCP:** будь-яке правило фаєрвола/клієнт, привʼязані до `172.17.61.218`, зламаються
> при зміні оренди. Перед продуктивом — MAC-резервація (`BC:24:11:56:33:4D`) або статика.

---

## 2. Обладнання

- **8 vCPU** (Xeon E5-2620 v4, прив'язані до NUMA-вузла 1), **32 GB RAM** (`balloon 0`).
- **GPU: NVIDIA Quadro P620, 2 GB VRAM** (passthrough `82:00.0` → у гості `01:00.0`), NUMA node 1.
- Диск 100 GB (thin, `nfs-nas202`).

> **2 ГБ VRAM — це головне обмеження всього нижчого.** Pascal (compute cap 6.1):
> CUDA 13 його вже не підтримує, vLLM неможливий (треба cc ≥ 7.0). Стек — llama.cpp / Ollama, GGUF Q4.

---

## 3. Програмний стек

| Компонент | Версія / деталь |
|---|---|
| ОС | Ubuntu 24.04.4 LTS |
| Драйвер NVIDIA | 580.173.02 (ветка 580 — остання з підтримкою Pascal; nouveau у blacklist) |
| CUDA toolkit | **12.6** (НЕ 13 — впаде на sm_61; `nvidia-smi` пише «CUDA 13.0» — це лише max API драйвера) |
| llama.cpp | зібрано з джерел, `-DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=61`, у `/opt/llama.cpp` |
| Корпоративний CA | `MODERN-CA-G2` встановлено у системний trust store + env-змінні для pip/requests |

**Egress:** `archive.ubuntu.com`, `github.com`, `pypi.org`, репозиторій NVIDIA, `huggingface.co`
доступні. `ollama.com` / `registry.ollama.ai` **блокуються** фаєрволом (Palo Alto) — важливо для
шляху інтеграції через Ollama (див. нижче: моделі імпортуються з локального GGUF, реєстр не потрібен).

### Корпоративний CA / TLS за фаєрволом (важливо для будь-яких нових інструментів)

Palo Alto робить вибіркове SSL-дешифрування; forward-trust серт `PAN-Decrypt-Cert` прив'язаний до
кореневого **`MODERN-CA-G2`**. Щоб дешифрований TLS не ламався:

- кореневий CA встановлено у системний store: `/usr/local/share/ca-certificates/MODERN-CA-G2.crt` +
  `update-ca-certificates`. Перевірено проти внутрішнього `mfaa.modern.org` → `Verify return code 0`.
- **Пастка certifi:** інструменти, встановлені через pip (`requests`, `huggingface_hub`), несуть власний
  `certifi` і **ігнорують системний store** → TLS ламається навіть після `update-ca-certificates`.
  Закрито системними env-змінними в `/etc/environment` + `/etc/environment.d/99-corporate-ca.conf`
  (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`
  → `/etc/ssl/certs/ca-certificates.crt`) і `/etc/pip.conf` `cert=` те саме. Будь-який новий
  Python-інструмент, що качає з інтернету, це успадкує; якщо додаєте venv — переконайтесь, що env
  успадковується або продублюйте `cert` у ньому.

### GPU / NUMA нотатки

Карта на NUMA-вузлі 1 (ядра 8–15). VM має `affinity`/`numa0` на вузол 1, але systemd-cpuset у гості
не делегований → жорсткої прив'язки vCPU немає (некритично). Вільна памʼять вузла 1 виглядає малою у
`numactl` (переважно reclaimable page-cache) — на завантаження моделі не впливає.

---

## 4. Поточний сервіс (llama.cpp)

`systemd`-юніт **`llama-server.service`** (enabled, автозапуск, `Restart=on-failure`), користувач `llama`.

```
модель:   Qwen2.5-Coder-3B-Instruct Q4_K_M
параметри: --n-gpu-layers 24 --ctx-size 8192 --threads 8 --host 0.0.0.0 --port 8080
API:      OpenAI-сумісний
```

**Ендпоінти** (`http://172.17.61.218:8080`):
- `GET  /v1/models` → `{"data":[{"id":"qwen2.5-coder-3b",...}]}`
- `POST /v1/chat/completions` (OpenAI-формат, підтримує `response_format={"type":"json_object"}`)
- `POST /v1/completions`
- `POST /completion` (нативний llama.cpp: підтримує `json_schema` / `grammar` для строгого JSON)
- `GET  /metrics` (Prometheus)

```bash
# перевірка
curl -s http://172.17.61.218:8080/v1/models
curl -s http://172.17.61.218:8080/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5-coder-3b","messages":[{"role":"user","content":"..."}],"temperature":0.2}'
```

> ⚠️ **API без автентифікації** на `0.0.0.0:8080` у VLAN 601. Для ширшого доступу — `--api-key`
> у юніті або обмеження джерел на фаєрволі.

---

## 5. Заміри продуктивності (P620 / 2 GB VRAM, генерація t/s)

| Модель | Конфіг | Промпт t/s | Генерація t/s | Примітка |
|---|---|---|---|---|
| Qwen2.5 1.5B | усе на GPU | 565 | **24.7** | найшвидша, слабша якість |
| Qwen2.5 3B | усе на GPU | 285 | 16.4 | **OOM при ctx ≥ 4096** — не для сервера |
| **Qwen2.5-Coder-3B** | ngl24, ctx8192 | 225 | **12.7** | ← поточний дефолт, VRAM 1593 MiB |
| Qwen2.5 3B | ngl20 частково | 206 | 11.0 | |
| Qwen2.5-Coder-7B | ngl≤8, CPU-bound | ~80 | **~4–5** | якісніша, для batch/offline |
| Qwen2.5 7B | CPU only | 79 | 4.3 | |

**Висновок по моделях під аналітику логів:** спеціалізованих «під логи» відкритих моделей
продакшн-рівня немає (LogLLM/LogGPT — академічні, без GGUF). Виграє coding-модель, бо лог —
технічний напівструктурований текст. Coder-3B правильно визначав severity/суть/першопричину на
тестових промптах; Coder-7B якісніший, але вчетверо повільніший.

### Чому Coder-3B, а не 1.5B (head-to-head, 2026-08-05)

Обидві моделі проганяли через той самий тріаж-промпт із примусовим JSON-виводом, як робить `app.py`:

| Сценарій | Очікуваний `score` | 1.5B | **Coder-3B** |
|---|---|---|---|
| Зовнішній брутфорс root (203.0.113.44) | високий | 0.9 ✓ | 0.8 ✓ |
| Свій працівник: 3× помилка паролю → успішний вхід | низький (FP) | **0.9 ✗** | **0.5 ✓** |

Обидві ловлять справжню атаку, але **1.5B не розрізняє** реальну загрозу і безпечний вхід свого
працівника — обом дала 0.9. Оскільки `app.py` авто-закриває при `score ≤ 0.6` і ескалює при `> 0.6`,
з 1.5B звичайний вхід працівника пішов би в ескалацію — рівно той alert fatigue, який усунуто комітом
«stop scoring employees' own fail-then-success as compromise». Coder-3B розрізнив (0.8 vs 0.5).
**Рішення: `fast_model` = Coder-3B.** Для цього use-case модель — це не косметика, а якість
автоматичного рішення закрити/ескалувати.

---

## 6. Моделі на диску (`/opt/models`, GGUF Q4_K_M)

```
qwen2.5-1.5b-instruct-q4_k_m.gguf              1.1G
qwen2.5-3b-instruct-q4_k_m.gguf                2.0G
qwen2.5-7b-instruct-q4_k_m-0000{1,2}-of-00002  4.5G
qwen2.5-coder-3b-instruct-q4_k_m.gguf          2.0G   ← дефолт сервісу
qwen2.5-coder-7b-instruct-q4_k_m-0000{1,2}     4.5G
nomic-embed-text-v1.5.Q4_K_M.gguf              81M    ← embeddings для RAG/retrieval
```

---

## 7. Інтеграція з цим middleware — ГОЛОВНЕ

`app.py` зараз викликає **Ollama**: `POST {ollama_url}/api/generate` з
`{model, prompt, stream:false, options:{num_ctx}, format:"json"}` і парсить `.response` як JSON
(`score`/`verdict`/`explanation`/`mitigated`). Конфіг у `/opt/qradar-middleware/config.json`:
`ollama_url`, `fast_model=qwen2.5-coder:7b`, `deep_model=qwen2.5-coder:32b`.

llm01 **не говорить** `/api/generate` — це llama.cpp з OpenAI `/v1`. Два шляхи:

### Шлях A (рекомендований) — поставити Ollama на llm01, middleware НЕ чіпати

Ollama говорить рідним `/api/generate`, тож `app.py` працює без змін коду.

1. Встановити Ollama на llm01 (бінарний інсталятор з GitHub — доступний; реєстр `ollama.com`
   заблокований, але **моделі імпортуються з наявних GGUF**, реєстр не потрібен):
   ```bash
   # приклад Modelfile для локального GGUF
   printf 'FROM /opt/models/qwen2.5-coder-3b-instruct-q4_k_m.gguf\nPARAMETER num_ctx 8192\n' > /tmp/Mf
   ollama create qwen2.5-coder-3b -f /tmp/Mf
   ```
2. Зупинити/вимкнути `llama-server.service` (щоб не конкурував за GPU) або лишити на іншому порті.
3. У `config.json`:
   ```json
   {
     "ollama_url": "http://172.17.61.218:11434",
     "fast_model": "qwen2.5-coder-3b",
     "deep_model": "qwen2.5-coder-7b"
   }
   ```
4. У `app.py` додати нові теги в `MODELS_MAX_CTX` та (для JSON-режиму) `MODELS_WITH_JSON_FORMAT`:
   ```python
   MODELS_MAX_CTX = { ..., "qwen2.5-coder-3b": 8192, "qwen2.5-coder-7b": 8192 }
   MODELS_WITH_JSON_FORMAT = { ..., "qwen2.5-coder-3b", "qwen2.5-coder-7b" }
   ```

### Шлях B — лишити llama.cpp, додати OpenAI-провайдера в `app.py`

Більше коду, але зберігає швидший llama-server. Дописати функцію на кшталт `ask_openai()`, що бʼє
`POST {base}/v1/chat/completions` з `response_format={"type":"json_object"}`, і провайдер `openai`
поряд з `ollama`/`vertex`. Конфіг: `ai_provider="openai"`, `openai_base="http://172.17.61.218:8080/v1"`.

### ⚠️ Реальність за розміром моделей (стосується обох шляхів)

Поточний `deep_model = qwen2.5-coder:32b` **на llm01 нездійсненний**: 32B-Q4 ≈ 20 GB → влізе в 32 GB
RAM, але лише CPU, ~1 t/s — непридатно. Рекомендація:
- `fast_model` → **Coder-3B** (GPU, ~12.7 t/s) для авто-тріажу.
- `deep_model` → **Coder-7B** (CPU, ~4–5 t/s) для ручного глибокого аналізу, **або** лишити deep на
  **Vertex/Gemini** (наявний fallback) — це найпрагматичніше: локально швидкий тріаж, важкі кейси в хмару.

### ⚠️ Обмеження контексту

Middleware розраховує `num_ctx` до 32768 (`MODELS_MAX_CTX`). llm01 підняте з `ctx 8192` — більший
контекст = більший KV-кеш = не влазить у 2 GB VRAM з offload. `app.py` уже ріже промпт під `num_ctx`
(`max_chars`), тож знизьте `MODELS_MAX_CTX` для локальних тегів до 8192, інакше промпт переповнить
контекст і якість впаде. Великі офенси доведеться агрегувати перед подачею.

---

## 8. Експлуатація

```bash
# статус / логи
systemctl status llama-server
journalctl -u llama-server -f

# зміна моделі: правимо --model та --n-gpu-layers у юніті, тоді
sudo systemctl edit --full llama-server && sudo systemctl restart llama-server

# швидкий бенчмарк
/opt/llama.cpp/build/bin/llama-bench -m /opt/models/<file>.gguf -ngl <N> -p 128 -n 64
```

**Орієнтири offload під 2 GB VRAM:** 1.5B → `ngl 99` (усе); 3B/Coder-3B → `ngl ~24` @ ctx8192;
7B/Coder-7B → `ngl ≤8` (переважно CPU). Понад це — `cudaMalloc failed: out of memory`.

---

## 9. Обмеження та ризики (чек-лист перед продуктивом)

- [ ] IP `172.17.61.218` — DHCP; зафіксувати (MAC-резервація / статика).
- [ ] API `:8080` без автентифікації — додати `--api-key` або firewall-обмеження джерел.
- [ ] `deep_model=32b` замінити на реалістичний (7B локально або Gemini).
- [ ] `MODELS_MAX_CTX` локальних тегів = 8192, не 32768.
- [ ] Визначитись A (Ollama, без коду) чи B (OpenAI-провайдер у `app.py`).
- [ ] GPU дає виграш лише для 3B; 7B практично CPU-bound — планувати таймаути (`timeout_seconds`) відповідно.
