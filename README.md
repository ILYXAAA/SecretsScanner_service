# Secrets Scanner Service

FastAPI-сервис для автоматического обнаружения секретов в репозиториях с использованием машинного обучения.

## 🔍 Описание

Сервис предназначен для сканирования репозиториев на предмет утечек секретов (API ключи, пароли, токены и т.д.). Поддерживает работу с GitHub и Azure DevOps, обеспечивает высокую производительность за счет multiproccess архитектуры.

### Redis
Для работы сервиса требуется поднятый Redis.
Самый простой вариант поднять docker:
```shell
docker run -d --name my-redis -p 6379:6379 redis:7 redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
```


## Архитектура системы

Система использует **Redis-based архитектуру** с отдельными worker процессами для обработки задач сканирования кода. Основные компоненты:

- **FastAPI сервер** - HTTP API для приема запросов
- **Redis** - очередь задач и хранилище состояний
- **Worker процессы** - выполнение задач сканирования
- **Admin API** - управление воркерами и мониторинг

## Поток обработки задач

### 1. Прием запроса на сканирование

```
POST /scan
POST /multi_scan  
POST /local_scan
```

**Этапы обработки запроса:**
- Валидация API ключа
- Проверка заполненности очереди (лимит: `MAX_WORKERS * 3`)
- Валидация существования `ref/branch` в репозитории (для remote сканирования)
- Резолв `commit` из `ref`
- Создание задачи в `Redis` с приоритетом

### 2. Структура задачи в Redis

```json
{
  "task_id": "task-abc12345",
  "status": "pending",
  "project_name": "MyProject",
  "repo_url": "https://github.com/user/repo",
  "commit": "a1b2c3d4...",
  "ref": "main", 
  "ref_type": "branch",
  "callback_url": "https://callback.example.com",
  "task_type": "scan|local_scan|multi_scan",
  "created_at": 1234567890,
  "timeout_at": 1234569690,
  "priority": 1,
  "original_data": {...}
}
```

### 3. Приоритетная очередь задач

**Redis структуры:**
- `tasks:queue` - Sorted Set с приоритетами (score = priority * 1000000 + timestamp)
- `tasks:all` - Hash со всеми данными задач
- `index:tasks:{status}` - Sets для быстрого поиска по статусам

**Приоритеты:**
- `1` - обычные scan запросы
- `2` - задачи из multi_scan (пониженный приоритет)

### 4. Worker процессы

#### Инициализация воркера
```python
worker_main(worker_id) ->
├── register_worker()  # Регистрация в Redis
├── heartbeat_loop()   # Фоновые heartbeat'ы
└── main_loop()        # Основной цикл обработки
```

### 5. Жизненный цикл задачи

```
pending -> downloading -> unpacking -> scanning -> ml_validation -> completed/failed
```

1. **`pending`** - задача в очереди
2. **`downloading`** - скачивание репозитория
3. **`unpacking`** - распаковка архива
4. **`scanning`** - сканирование правилами
5. **`ml_validation`** - ML проверка результатов
6. **`completed`** - отправка результатов на callback
7. **`failed`** - ошибка на любом этапе

### 6. Atomic операции в Redis

Для обеспечения консистентности используются **Lua скрипты**:

- **pop_task()** - атомарное получение задачи воркером
- **update_task_status()** - обновление статуса с индексами
- **retry_task()** - возврат failed задачи в очередь

### 7. Background процессы

#### Main сервер
```python
background_maintenance():
├── timeout_check()     # Проверка просроченных задач
├── worker_health()     # Проверка статусов воркеров  
└── cleanup_tasks()     # Удаление старых задач
```

#### Worker процессы
```python
heartbeat_thread():
├── update_worker_heartbeat()  # Обновление last_heartbeat
├── check_worker_commands()    # Проверка команд (pause/shutdown)
└── cleanup_temp_files()       # Очистка временных файлов
```

### 8. Управление воркерами

#### Admin API endpoints
```ruby
GET  /admin/workers               # Список всех воркеров
POST /admin/workers/add           # Добавить воркер (с проверкой MAX_WORKERS)
POST /admin/workers/{id}/stop     # Graceful shutdown
POST /admin/workers/{id}/kill     # Force terminate
POST /admin/workers/{id}/pause    # Приостановить обработку
POST /admin/workers/{id}/resume   # Возобновить обработку
```

#### Команды воркерам
Команды передаются через Redis ключи `worker_commands:{worker_id}`:
- `shutdown` - graceful остановка
- `pause` - прекратить брать новые задачи
- `resume` - возобновить обработку


## Конфигурация через .env

### Основные настройки
```bash
# Тип хаба и сетевые настройки
HubType='Azure'                   # Azure | GitHub - тип репозитория
HOST='127.0.0.1'                 # Хост сервиса
PORT='8001'                      # Порт сервиса
REDIS_URL='redis://127.0.0.1:6379' # URL до поднятого Redis
TEMP_DIR='tmp/'                   # Папка для распаковки архивов (автоудаление)
```

### Аутентификация и безопасность
```bash
API_KEY='***'                     # API ключ для доступа к сервису
ADMIN_API_KEY='***'               # Ключ для /admin эндпоинтов (X-API-Key)
LOGIN_KEY='***'                   # Ключ шифрования логина NTLM Auth
PASSWORD_KEY='***'                # Ключ шифрования пароля NTLM Auth  
PAT_KEY='***'                     # Ключ шифрования PAT токена
```

### Управление воркерами
```bash
MAX_WORKERS='10'                  # Максимальное количество воркеров
STARTUP_WORKERS='2'               # Воркеров при старте сервиса
VALIDATION_THREADS_NUMBER='5'     # Потоки для валидации запросов в main.py
```

### Временные настройки и таймауты
```bash
# Задачи и их жизненный цикл
TASK_TIMEOUT_SECONDS='1800'       # Таймаут задач (30 минут)
TASK_RETENTION_DAYS='7'           # Срок хранения завершенных задач
WORKER_HEARTBEAT_INTERVAL='20'    # Интервал heartbeat воркеров

# Background процессы maintenance
CLEANUP_INTERVAL_SECONDS='600'    # Очистка зависших/старых задач (10 мин)
TIMEOUT_CHECK_INTERVAL='120'      # Проверка таймаутов задач (2 мин)
WORKER_CHECK_INTERVAL='240'       # Проверка состояния воркеров (4 мин)
```

## Запуск
```shell
python run.py
```