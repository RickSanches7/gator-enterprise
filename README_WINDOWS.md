# 🐊 GATOR PRO Enterprise v2.0 — Установка на Windows

## Что нужно установить (только 1 программа)

### Docker Desktop для Windows

1. Скачай: **https://www.docker.com/products/docker-desktop/**
2. Запусти установщик (нужны права администратора)
3. При установке выбери: **"Use WSL 2 instead of Hyper-V"** ✅
4. После установки перезагрузи компьютер
5. Запусти Docker Desktop из меню Пуск
6. Дождись зелёной иконки кита в системном трее (правый нижний угол)

**Минимальные требования:**
- Windows 10 версия 1903+ или Windows 11
- 8 GB RAM (рекомендуется 16 GB)
- 10 GB свободного места на диске
- Включена виртуализация в BIOS (обычно уже включена)

---

## Запуск GATOR PRO (2 шага)

### Шаг 1 — Распакуй архив
Распакуй `gator-enterprise-v2.0-FINAL.tar.gz` в любую папку, например:
```
C:\Users\ИмяПользователя\gator-enterprise\
```

> 💡 **Совет:** Используй [7-Zip](https://www.7-zip.org/) для распаковки .tar.gz на Windows

### Шаг 2 — Запусти установку

**Вариант A — двойной клик (проще):**
```
Дважды кликни на  setup.bat
```

**Вариант B — PowerShell (рекомендуется):**
```
Правый клик на setup.ps1 → "Запустить с помощью PowerShell"
```

**Вариант C — через командную строку:**
```cmd
cd C:\путь\до\gator-enterprise
docker compose up -d
```

---

## После запуска

Открой браузер и перейди на:

| Сервис | URL |
|--------|-----|
| 🌐 **Интерфейс** | http://localhost:8080 |
| ⚡ **API** | http://localhost:8000 |
| 📚 **API Документация** | http://localhost:8000/api/docs |
| 🌸 **Мониторинг задач** | http://localhost:5555 |

**Логин:** `admin`  
**Пароль:** `GatorAdmin2024!`  
⚠️ **Смени пароль сразу после первого входа!**

---

## Управление

| Действие | Команда |
|----------|---------|
| **Запуск** | двойной клик `setup.bat` или `docker compose up -d` |
| **Остановка** | двойной клик `stop.bat` или `docker compose down` |
| **Логи** | двойной клик `logs.bat` или `docker compose logs -f backend` |
| **Рестарт** | `docker compose restart` |
| **Обновление** | `docker compose build && docker compose up -d` |

---

## Настройка Telegram уведомлений (необязательно)

1. Открой файл `.env` в Блокноте или VS Code
2. Найди строки:
   ```
   TELEGRAM_BOT_TOKEN=
   TELEGRAM_CHAT_ID=
   ```
3. Создай бота через [@BotFather](https://t.me/BotFather) в Telegram
4. Получи chat_id: отправь боту любое сообщение, затем открой:
   `https://api.telegram.org/bot<ТВОЙ_ТОКЕН>/getUpdates`
5. Вставь значения в .env и перезапусти: `docker compose restart worker`

---

## Настройка NVD CVE API (необязательно, ускоряет поиск CVE)

1. Зарегистрируйся на https://nvd.nist.gov/developers/request-an-api-key (бесплатно)
2. Получи API ключ на email
3. Добавь в `.env`:
   ```
   NVD_API_KEY=твой-api-ключ
   ```
4. Рестарт: `docker compose restart worker`

---

## Возможные проблемы

### ❌ "Docker not found"
→ Установи Docker Desktop: https://www.docker.com/products/docker-desktop/

### ❌ Docker не запускается / ошибка WLS2
→ Запусти в PowerShell от администратора:
```powershell
wsl --install
wsl --update
```
→ Перезагрузи компьютер

### ❌ "Port already in use" (порт занят)
→ Проверь что порты 8080, 8000, 5555 свободны:
```cmd
netstat -ano | findstr "8080"
```
→ Или измени порты в `docker-compose.yml`

### ❌ Медленная сборка / зависает
→ В Docker Desktop: Settings → Resources → увеличь Memory до 4-8 GB

### ❌ Контейнеры падают сразу после старта
```cmd
docker compose logs backend
docker compose logs worker
```
→ Пришли вывод на GatorSupport@ya.ru

### ❌ Страница не открывается после запуска
→ Подожди 30-60 секунд — сервисы инициализируются
→ Проверь: `docker compose ps` — все должны быть "running" или "healthy"

---

## Данные и безопасность

- Все данные хранятся в Docker volumes на твоём компьютере
- База данных: зашифрована паролем из `.env`
- Отчёты: сохраняются в папке `reports/` внутри контейнера
- При `docker compose down -v` — ВСЕ данные удаляются
- При `docker compose down` — данные сохраняются

---

## Структура папки

```
gator-enterprise/
├── setup.bat          ← Запуск на Windows (двойной клик)
├── setup.ps1          ← Запуск через PowerShell
├── stop.bat           ← Остановка
├── logs.bat           ← Просмотр логов
├── docker-compose.yml ← Конфигурация сервисов
├── .env               ← Настройки (токены, пароли)
├── .env.example       ← Шаблон настроек
├── backend/           ← Python FastAPI + все модули сканирования
├── frontend/          ← Web интерфейс
└── docker/            ← Конфиги nginx, postgres
```

---

*GATOR PRO Enterprise v2.0 — gator.uz | GatorSupport@ya.ru*
