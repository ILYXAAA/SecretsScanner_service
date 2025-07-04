# Secrets Scanner Service

FastAPI-сервис для автоматического обнаружения секретов в репозиториях с использованием машинного обучения.

## 🔍 Описание

Сервис предназначен для сканирования репозиториев на предмет утечек секретов (API ключи, пароли, токены и т.д.). Поддерживает работу с GitHub и Azure DevOps, обеспечивает высокую производительность за счет многопроцессорной архитектуры.

## 🔁 Процесс сканирования (кратко)

### 1. Поток обработки запроса

1. **HTTP запрос** → FastAPI принимает `/scan`
2. **Валидация** → проверяет существование ветки/коммита. Если **не найдено** ❌, отправляет ошибку валидации. Если **ок** ✅, то идем далее.
3. **Очередь** → добавляет задачу в `asyncio.Queue`
4. **Воркер берет задачу** → один из 10 воркеров (по умолчанию) забирает из очереди
5. **Скачивание** → `ThreadPoolExecutor` скачивает репозиторий. `ThreadPoolExecutor` используется т.к. это `I/O` операция.
6. **Сканирование** → `ProcessPoolExecutor` запускает отдельный процесс. Используется `ProcessPoolExecutor` т.к. это CPU операция:
   - Загружает ML модель (Singleton)
   - Сканирует файлы батчами по 5
   - Применяет regex правила
   - Фильтрует ML моделью
7. **Результат** → отправляет callback на указанный URL

### Параллелизм

- **10 запросов одновременно** → 10 воркеров обрабатывают параллельно
- **Каждый воркер** = отдельный процесс со своей моделью ~`51.7 MB`
- **Больше 10 запросов** → ждут в очереди свободного воркера. При мульти-сканировании используется 1 воркер. Т.е. максимум одновременно можно запускать `10 сканов` (мультисканов/обычных сканов, не важно)

## 🏗️ Архитектура

### Многопроцессорная система
- **Основной процесс**: FastAPI сервер, обработка HTTP запросов
- **Download Executor**: ThreadPoolExecutor для скачивания репозиториев
- **Model Executor**: ProcessPoolExecutor для CPU-интенсивных операций (сканирование + ML)
- **Асинхронная очередь**: Управление задачами между процессами

### Компоненты системы

#### 1. **API Layer** (`main.py`)
- **Endpoints**: `/scan`, `/multi_scan`, `/local_scan`
- **Аутентификация**: API ключи через заголовки
- **Управление конфигурацией**: CRUD операции для правил сканирования
- **Health checks**: Мониторинг состояния очереди и воркеров

#### 2. **Queue Worker** (`queue_worker.py`)
- **Task Queue**: Асинхронная очередь для обработки запросов
- **Multi-processing**: Разделение I/O (Input/Output) и CPU операций
- **Sequential Multi-scan**: Последовательная обработка множественных репозиториев
- **Callback Management**: Отправка результатов на внешние URL

#### 3. **Repository Handler** (`repo_utils.py`)
- **Multi-platform Support**: GitHub и Azure DevOps
- **Reference Resolving**: Автоматический резолв веток, тегов, коммитов
- **Authentication**: PAT-токен, NTLM, Negotiate
- **Safe Extraction**: Фильтрация опасных файлов при распаковке

#### 4. **Scanner Engine** (`scanner.py`)
- **Regex Rules**: Настраиваемые правила поиска секретов
- **Batch Processing**: Параллельная обработка файлов
- **File Filtering**: Исключение файлов по расширениям и именам
- **False Positive Detection**: Система фильтрации ложных срабатываний

#### 5. **ML Classifier** (`model_loader.py`)
- **Scikit-learn Model**: TF-IDF + Logistic Regression
- **Singleton Pattern**: Один экземпляр модели на процесс
- **Auto-training**: Автоматическое обучение при отсутствии модели
- **Confidence Scoring**: Классификация по уровням достоверности

#### 6. **Security Layer** (`secure_save.py`)
- **Fernet Encryption**: Шифрование токенов и паролей
- **Environment Keys**: Ключи шифрования в .env файлах
- **Setup Wizard**: Мастер первичной настройки

## 🔧 Технологический стек

### Backend Framework
- **FastAPI**: Асинхронный веб-фреймворк
- **Pydantic**: Валидация данных и моделей
- **AsyncIO**: Асинхронность

### Многопроцессорность
- **ThreadPoolExecutor**: I/O операции (скачивание)
- **ProcessPoolExecutor**: CPU операции (сканирование)
- **Asyncio.Queue**: Межпроцессорная очередь

### Машинное обучение
- **Scikit-learn**: ML фреймворк
- **TF-IDF Vectorizer**: Векторизация текста (char n-grams 3-5)
- **Logistic Regression**: Бинарная классификация секретов
- **Joblib**: Сериализация моделей

### Примерные расчеты занимаемой памяти, при загрузке синглтон модели на 10 воркеров, при 2-х датасетах, по 46к строк каждый:
```ruby
MODEL MEMORY (ACTUAL):
[INFO] Vectorizer: 37.2 MB
[INFO] Model: 14.5 MB
[INFO] Vocabulary: 1,902,401 terms
[INFO] Total per process: 51.7 MB
[INFO] Estimated for 10 workers: 517.3 MB
```
#### Общая занимаемая память ~ `520МБ`

### Работа с репозиториями
- **Requests**: HTTP клиент для API
- **Git**: Резолвинг коммитов по тегам/веткам
- **ZipFile**: Обработка архивов

### Аутентификация
- **requests-ntlm**: NTLM аутентификация
- **requests-negotiate-sspi**: Kerberos/SPNEGO
- **HTTPBasicAuth**: Basic Auth для PAT токенов

### Шифрование и безопасность
- **Cryptography.Fernet**: Симметричное шифрование
- **python-dotenv**: Управление переменными окружения
- **Secrets**: Криптографически стойкие сравнения

### Конфигурация
- **PyYAML**: Обработка YAML конфигураций
- **AIOFiles**: Асинхронная работа с файлами

## 🚀 Процесс работы

### 1. Инициализация
```
FastAPI Start → Load Model → Start Workers → Ready
```

### 2. Обработка запроса
```
HTTP Request → Validate → Queue → Download → Scan → ML Filter → Callback
```

### 3. Детальный flow

#### Single Scan (`/scan`)
1. **Валидация**: Проверка существования ветки/тега/коммита
2. **Queue**: Добавление в асинхронную очередь
3. **Download**: Скачивание в ThreadPoolExecutor
4. **Scan**: Сканирование в ProcessPoolExecutor
5. **ML Classification**: Фильтрация ML моделью
6. **Callback**: Отправка результатов

#### Multi Scan (`/multi_scan`)
1. **Batch Validation**: Проверка всех репозиториев
2. **Sequential Processing**: Последовательная обработка
3. **Individual Callbacks**: Отдельный callback для каждого репозитория

#### Local Scan (`/local_scan`)
1. **ZIP Upload**: Получение файла через multipart/form-data
2. **Extract**: Распаковка во временную директорию
3. **Scan**: Аналогично remote сканированию
4. **Cleanup**: Удаление временных файлов

## 🔍 ML Модель

### Архитектура
- **Input**: Строки с подозрительными секретами
- **Vectorization**: TF-IDF с символьными n-граммами (3-5)
- **Model**: Logistic Regression (max_iter=1000)
- **Output**: Probability + Binary Classification

### Классификация уровней
- **High**: Уверенные секреты (pred=1) или неуверенные случаи
- **Potential**: Уверенные не-секреты (pred=0, confidence>0.8)

### Обучение
- **Datasets**: Положительные и отрицательные примеры
- **Auto-training**: При отсутствии готовой модели
- **Persistence**: Сохранение через joblib

## ⚙️ Конфигурация

### Файлы настроек
- `rules.yml`: Regex правила поиска
- `excluded_extensions.yml`: Исключенные расширения файлов
- `excluded_files.yml`: Исключенные имена файлов
- `false-positive.yml`: Правила фильтрации ложных срабатываний

### Переменные окружения
```python
HubType='Azure' # Azure | GutHub
LOGIN_KEY='***' # Ключ для шифрования логина NTLM Auth
PASSWORD_KEY='***' # Ключ для шифрования пароля NTLM Auth
PAT_KEY='***' # Ключ для шифрования PAT токена
HOST='127.0.0.1' # Хост микросервиса
PORT='8001' # Порт микросервиса
API_KEY='***' # API ключ для доступа к этому микросервису из вне
MAX_WORKERS='10' # Максимальное количество запущенных воркеров
TEMP_DIR='tmp/' # Папка для распаковки архивов репозиториев (автоматически удаляются после сканирования)
```

### Шифрование
- Все токены и пароли хранятся в зашифрованном виде
- Ключи шифрования в .env файле
- Мастер настройки при первом запуске

## 🔒 Безопасность

### Обработка файлов
- Фильтрация потенциально опасных файлов при распаковке
- Ограничение длины путей (MAX_PATH = 250)
- Исключение absolute paths и ".." в архивах

### Аутентификация
- API ключи с криптографически стойким сравнением
- Множественные методы аутентификации для репозиториев
- Шифрование всех чувствительных данных

### Ограничения сканирования
- Максимум `100` секретов на файл
- Ограничение длины строк (`7000` символов)
- Хеширование при превышении лимитов, отправка в виде одного секрета, для проверки специалистом (чтобы не забивать отчеты потенциально одинаковыми `false-positive` секретами)

## 📊 Производительность

### Оптимизации
- **Параллельная обработка**: Файлы сканируются `батчами по 5`. Каждая пятерка сканируется параллельно. Следующая пятерка ждет завершения предыдущей. **Цель:** `Контроль нагрузки` - не сканировать все файлы одновременно, чтобы избежать перегрузки памяти и CPU.
- **Разделение нагрузки**: I/O и CPU операции в разных пулах
- **Кеширование модели**: Singleton pattern для ML модели
- **Асинхронность**: Неблокирующие операции везде где возможно

### Мониторинг
- Health endpoint с метриками очереди
- Подробное логирование времени выполнения
- Отслеживание количества обработанных файлов