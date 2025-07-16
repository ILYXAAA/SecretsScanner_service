#!/usr/bin/env python3
import yaml
import random
import string
import base64
import uuid
import jwt
import re
from faker import Faker
from tqdm import tqdm

fake = Faker()

# Константы
N = 100_000
OUTPUT_FILE = "Dataset_Secrets.txt"

def load_yaml_file(filename):
    """Загрузка YAML файла"""
    with open(filename, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def generate_random_string(length, chars=string.ascii_letters + string.digits):
    """Генерация случайной строки"""
    return ''.join(random.choice(chars) for _ in range(length))

def generate_hex_string(length):
    """Генерация hex строки"""
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

def generate_jwt():
    """Генерация JWT токена"""
    payload = {
        "sub": fake.uuid4(),
        "name": fake.name(),
        "iat": random.randint(1600000000, 1700000000),
        "exp": random.randint(1700000000, 1800000000)
    }
    secret = generate_random_string(32)
    return jwt.encode(payload, secret, algorithm="HS256")

def generate_password(length=None):
    """Генерация пароля со спецсимволами"""
    if length is None:
        length = random.randint(12, 16)
    
    # Безопасные спецсимволы
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    chars = string.ascii_letters + string.digits + special_chars
    
    # Гарантируем наличие разных типов символов
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(special_chars)
    ]
    
    # Добавляем остальные символы
    for _ in range(length - 4):
        password.append(random.choice(chars))
    
    random.shuffle(password)
    return ''.join(password)

def generate_token(length=None):
    """Генерация обычного токена"""
    if length is None:
        length = random.randint(32, 64)
    return generate_random_string(length)

def generate_telegram_token():
    """Генерация Telegram токена"""
    bot_id = random.randint(100000000, 999999999)
    token_part = generate_random_string(35, string.ascii_letters + string.digits + '_-')
    return f"{bot_id}:{token_part}"

def generate_private_key():
    """Генерация приватного ключа"""
    key_data = generate_random_string(random.randint(100, 200), 
                                    string.ascii_letters + string.digits + '+/=')
    return f"-----BEGIN PRIVATE KEY-----{key_data}-----END PRIVATE KEY-----"

def generate_ssh_private_key():
    """Генерация SSH приватного ключа"""
    key_data = generate_random_string(random.randint(100, 200), 
                                    string.ascii_letters + string.digits + '+/=')
    return f"-----BEGIN OPENSSH PRIVATE KEY-----{key_data}-----END OPENSSH PRIVATE KEY-----"

def generate_bearer_token():
    """Генерация Bearer токена"""
    return generate_random_string(random.randint(40, 80))

def generate_github_token():
    """Генерация GitHub токена"""
    return f"ghp_{generate_random_string(36)}"

def generate_basic_auth():
    """Генерация Basic Auth"""
    prefixes = ['user', 'admin', 'test', 'demo', 'guest']
    suffixes = ['123', '456', '2023', '2024', 'prod', 'dev']
    login = random.choice(prefixes) + random.choice(suffixes)
    password = generate_password(12)
    auth_string = f"{login}:{password}"
    return base64.b64encode(auth_string.encode()).decode()

def generate_log_pass():
    """Генерация login:password"""
    prefixes = ['user', 'admin', 'test', 'demo', 'guest']
    suffixes = ['123', '456', '2023', '2024', 'prod', 'dev']
    login = random.choice(prefixes) + random.choice(suffixes)
    password = generate_password(12)
    return f"{login}:{password}"

def generate_url():
    """Генерация URL"""
    protocols = ['http', 'https']
    tlds = [".ru", ".рф", ".com", ".net", ".org", ".su", ".biz", ".info", ".site", ".store", ".pro", ".online", ".moscow", ".ru.com", ".me", ".name", ".club", ".tech", ".app", ".io"]
    paths = ['', '/api', '/v1', '/auth', '/data', '/users']
    
    protocol = random.choice(protocols)
    domain_name = fake.domain_word()
    tld = random.choice(tlds)
    path = random.choice(paths)
    
    return f"{protocol}://{domain_name}{tld}{path}"

def generate_slack_token():
    """Генерация Slack токена"""
    prefixes = ['xoxb-', 'xoxp-', 'xoxa-', 'xoxs-']
    prefix = random.choice(prefixes)
    token_part = generate_random_string(32, string.digits)
    return f"{prefix}{token_part}"

def generate_keytab():
    """Генерация Keytab"""
    return base64.b64encode(generate_random_string(64).encode()).decode()

def generate_hmac():
    """Генерация HMAC"""
    return generate_hex_string(64)

def generate_login():
    """Генерация логина"""
    return fake.user_name()

def generate_basic_auth():
    """Генерация Basic Auth"""
    login = fake.user_name()
    password = generate_password(12)
    auth_string = f"{login}:{password}"
    return base64.b64encode(auth_string.encode()).decode()

def generate_log_pass():
    """Генерация login:password"""
    login = fake.user_name()
    password = generate_password(12)
    return f"{login}:{password}"

def generate_uuid():
    """Генерация UUID"""
    return str(uuid.uuid4())

def get_secret_value(secret_type, length_spec=None):
    """Получение значения секрета по типу"""
    if length_spec:
        # Парсинг длины [8:20]
        match = re.match(r'\[(\d+):(\d+)\]', length_spec)
        if match:
            min_len, max_len = int(match.group(1)), int(match.group(2))
            length = random.randint(min_len, max_len)
        else:
            length = None
    else:
        length = None
    
    generators = {
        'JWT': generate_jwt,
        'PASSWORD': lambda: generate_password(length),
        'TOKEN': lambda: generate_token(length),
        'TELEGRAM_TOKEN': generate_telegram_token,
        'PRIVATE_KEY': generate_private_key,
        'SSH_PRIVATE_KEY': generate_ssh_private_key,
        'BEARER_TOKEN': generate_bearer_token,
        'GITHUB_TOKEN': generate_github_token,
        'BASIC_AUTH': generate_basic_auth,
        'LOG:PASS': generate_log_pass,
        'URL': generate_url,
        'SLACK_TOKEN': generate_slack_token,
        'KEYTAB': generate_keytab,
        'HMAC': generate_hmac,
        'LOGIN': generate_login,
        'UUID': generate_uuid
    }
    
    return generators.get(secret_type, lambda: generate_random_string(32))()

def replace_placeholders(pattern, static_data):
    """Замена плейсхолдеров в паттерне"""
    result = pattern
    
    # Замена статических данных
    for key, values in static_data.items():
        placeholder = f"${key.upper()}$"
        if placeholder in result:
            result = result.replace(placeholder, random.choice(values))
    
    # Замена секретов с возможной длиной
    secret_pattern = r'\$([A-Z_:]+)\$(\[\d+:\d+\])?'
    matches = re.findall(secret_pattern, result)
    
    for secret_type, length_spec in matches:
        full_placeholder = f"${secret_type}${length_spec}"
        secret_value = get_secret_value(secret_type, length_spec if length_spec else None)
        result = result.replace(full_placeholder, secret_value)
    
    return result

def generate_secrets():
    """Основная функция генерации секретов"""
    # Загрузка конфигурации
    patterns = load_yaml_file('secrets_patterns.yaml')
    static_data = load_yaml_file('secrets_static_data.yaml')
    
    # Создание списка всех паттернов
    all_patterns = []
    for category, pattern_list in patterns.items():
        for pattern in pattern_list:
            all_patterns.append(pattern)
    
    # Генерация секретов
    secrets = []
    pattern_index = 0
    
    for i in tqdm(range(N), desc="Генерация секретов"):
        pattern = all_patterns[pattern_index % len(all_patterns)]
        secret = replace_placeholders(pattern, static_data)
        # Удаляем переносы строк
        secret = secret.replace('\n', '').replace('\r', '')
        secrets.append(secret)
        pattern_index += 1
    
    # Запись в файл
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for secret in secrets:
            f.write(secret + '\n')
    
    print(f"Сгенерировано {len(secrets)} секретов в файле {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_secrets()