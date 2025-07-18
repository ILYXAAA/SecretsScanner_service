#!/usr/bin/env python3
import yaml
import random
import string
import uuid
import re
from datetime import datetime, timedelta
from faker import Faker
from tqdm import tqdm

fake = Faker()

# Константы
N = 100_000
OUTPUT_FILE = "Dataset_NonSecrets.txt"

def load_yaml_file(filename):
    """Загрузка YAML файла"""
    with open(filename, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def generate_random_string(length, chars=string.ascii_letters + string.digits):
    """Генерация случайной строки"""
    return ''.join(random.choice(chars) for _ in range(length))

def generate_random_word():
    """Генерация случайного слова"""
    return fake.word()

def generate_public_url():
    """Генерация публичного URL"""
    protocols = ['http', 'https']
    domains = ['example.com', 'test.org', 'demo.net', 'sample.io', 'public.co']
    paths = ['', '/docs', '/api', '/help', '/about', '/contact', '/blog', '/news']
    
    protocol = random.choice(protocols)
    domain = random.choice(domains)
    path = random.choice(paths)
    
    return f"{protocol}://{domain}{path}"

def generate_user_id():
    """Генерация ID пользователя"""
    formats = [
        lambda: str(random.randint(1000, 999999)),
        lambda: f"user_{random.randint(100, 9999)}",
        lambda: str(uuid.uuid4()),
        lambda: f"usr_{generate_random_string(8)}",
        lambda: fake.user_name() + str(random.randint(10, 99))
    ]
    return random.choice(formats)()

def generate_hash_id():
    """Генерация обычного хеша (не секретного)"""
    return generate_random_string(random.choice([8, 16, 32]), string.ascii_lowercase + string.digits)

def generate_version():
    """Генерация версии ПО"""
    major = random.randint(1, 10)
    minor = random.randint(0, 20)
    patch = random.randint(0, 50)
    
    formats = [
        f"{major}.{minor}.{patch}",
        f"v{major}.{minor}.{patch}",
        f"{major}.{minor}",
        f"{major}.{minor}.{patch}-beta",
        f"{major}.{minor}.{patch}-rc{random.randint(1, 5)}"
    ]
    return random.choice(formats)

def generate_timestamp():
    """Генерация временной метки"""
    now = datetime.now()
    delta = timedelta(days=random.randint(-365, 30))
    timestamp = now + delta
    
    formats = [
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        timestamp.strftime("%Y-%m-%d"),
        timestamp.strftime("%H:%M:%S"),
        str(int(timestamp.timestamp())),
        timestamp.isoformat()
    ]
    return random.choice(formats)

def generate_file_path():
    """Генерация пути к файлу"""
    paths = [
        f"/var/log/{fake.word()}.log",
        f"/etc/{fake.word()}.conf",
        f"/home/user/{fake.word()}.txt",
        f"C:\\Users\\{fake.first_name()}\\Documents\\{fake.word()}.docx",
        f"./src/{fake.word()}.py",
        f"../config/{fake.word()}.json",
        f"/tmp/{fake.word()}_{random.randint(1, 999)}.tmp",
        f"./assets/images/{fake.word()}.png"
    ]
    return random.choice(paths)

def generate_log_level():
    """Генерация уровня логирования"""
    levels = ["DEBUG", "INFO", "WARN", "ERROR", "FATAL", "TRACE"]
    return random.choice(levels)

def generate_int(length_spec=None):
    """Генерация случайного числа"""
    if length_spec:
        match = re.match(r'\[(\d+):(\d+)\]', length_spec)
        if match:
            min_val, max_val = int(match.group(1)), int(match.group(2))
            return str(random.randint(min_val, max_val))
    return str(random.randint(1, 999))

def generate_fake_jwt():
    """Генерация строки похожей на JWT но не являющейся им"""
    words = [fake.word().lower() for _ in range(random.randint(3, 6))]
    part1 = ''.join(words)
    
    words = [fake.word().lower() for _ in range(random.randint(3, 6))]
    part2 = ''.join(words)
    
    words = [fake.word().lower() for _ in range(random.randint(3, 6))]
    part3 = ''.join(words)
    
    return f"{part1}.{part2}.{part3}"

def generate_language():
    """Генерация кода языка"""
    languages = ["en", "ru", "de", "fr", "es", "it", "pt", "zh", "ja", "ko", "ar", "hi"]
    return random.choice(languages)

def generate_user_agent():
    """Генерация User Agent"""
    return fake.user_agent()

def generate_os_version():
    """Генерация версии ОС"""
    os_versions = [
        f"Windows {random.randint(7, 11)}.{random.randint(0, 9)}",
        f"macOS {random.randint(10, 14)}.{random.randint(0, 9)}",
        f"Ubuntu {random.randint(18, 24)}.{random.randint(1, 12):02d}",
        f"CentOS {random.randint(6, 8)}.{random.randint(0, 9)}",
        f"iOS {random.randint(13, 17)}.{random.randint(0, 9)}",
        f"Android {random.randint(8, 14)}.{random.randint(0, 9)}"
    ]
    return random.choice(os_versions)

def get_non_secret_value(value_type, length_spec=None):
    """Получение значения НЕ-секрета по типу"""
    generators = {
        'PUBLIC_URL': generate_public_url,
        'USER_ID': generate_user_id,
        'HASH_ID': generate_hash_id,
        'VERSION': generate_version,
        'TIMESTAMP': generate_timestamp,
        'FILE_PATH': generate_file_path,
        'LOG_LEVEL': generate_log_level,
        'INT': lambda: generate_int(length_spec),
        'WORD': generate_random_word,
        'FAKE_JWT': generate_fake_jwt,
        'LANGUAGE': generate_language,
        'USER_AGENT': generate_user_agent,
        'OS_VERSION': generate_os_version
    }
    
    return generators.get(value_type, lambda: generate_random_string(10))()

def replace_placeholders(pattern, static_data):
    """Замена плейсхолдеров в паттерне"""
    result = pattern
    
    # Замена статических данных
    for key, values in static_data.items():
        placeholder = f"${key.upper()}$"
        if placeholder in result:
            result = result.replace(placeholder, random.choice(values))
    
    # Замена генерируемых значений с возможной длиной
    value_pattern = r'\$([A-Z_]+)\$(\[\d+:\d+\])?'
    matches = re.findall(value_pattern, result)
    
    for value_type, length_spec in matches:
        full_placeholder = f"${value_type}${length_spec}"
        value = get_non_secret_value(value_type, length_spec if length_spec else None)
        result = result.replace(full_placeholder, str(value))
    
    return result

def generate_non_secrets():
    """Основная функция генерации НЕ-секретов"""
    # Загрузка конфигурации
    patterns = load_yaml_file('non_secrets_patterns.yaml')
    static_data = load_yaml_file('non_secrets_static_data.yaml')
    
    # Создание списка всех паттернов
    all_patterns = []
    for category, pattern_list in patterns.items():
        for pattern in pattern_list:
            all_patterns.append(pattern)
    
    # Генерация НЕ-секретов
    non_secrets = []
    pattern_index = 0
    
    for i in tqdm(range(N), desc="Генерация НЕ-секретов"):
        pattern = all_patterns[pattern_index % len(all_patterns)]
        non_secret = replace_placeholders(pattern, static_data)
        # Удаляем переносы строк
        non_secret = non_secret.replace('\n', '').replace('\r', '')
        non_secrets.append(non_secret)
        pattern_index += 1
    
    # Запись в файл
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for non_secret in non_secrets:
            f.write(non_secret + '\n')
    
    print(f"Сгенерировано {len(non_secrets)} НЕ-секретов в файле {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_non_secrets()