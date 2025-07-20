#!/usr/bin/env python3
import yaml
import random
import string
import base64
import uuid
import jwt
import re
import shutil
import os
from faker import Faker
from tqdm import tqdm
from collections import defaultdict

fake = Faker()

# Константы
N = 264_385
OUTPUT_FILE = "Dataset_Secrets.txt"
RULES_FILE = "../Settings/rules.yml"
PATTERNS_FILE = "secrets_patterns.yaml"
STATIC_DATA_FILE = "secrets_static_data.yaml"

def load_yaml_file(filename):
    """Загрузка YAML файла"""
    with open(filename, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def save_yaml_file(filename, data):
    """Сохранение YAML файла"""
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def load_rules():
    """Загрузка правил из rules.yml"""
    rules = load_yaml_file(RULES_FILE)
    compiled_rules = {}
    
    for rule in rules:
        rule_id = rule['id']
        pattern = rule['pattern']
        message = rule['message']
        compiled_rules[rule_id] = {
            'pattern': re.compile(pattern),
            'message': message,
            'original_pattern': pattern
        }
    
    return compiled_rules

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
    login = fake.user_name()
    password = generate_password(12)
    auth_string = f"{login}:{password}"
    return base64.b64encode(auth_string.encode()).decode()

def generate_log_pass():
    """Генерация login:password"""
    login = fake.user_name()
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
    # Генерируем токен в формате xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}
    part1 = generate_random_string(12, string.digits)
    part2 = generate_random_string(12, string.digits)
    part3 = generate_random_string(12, string.digits)
    part4 = generate_random_string(32, string.ascii_lowercase + string.digits)
    return f"{prefix}{part1}-{part2}-{part3}-{part4}"

def generate_keytab():
    """Генерация Keytab"""
    return base64.b64encode(generate_random_string(64).encode()).decode()

def generate_hmac():
    """Генерация HMAC"""
    return generate_hex_string(64)

def generate_login():
    """Генерация логина"""
    return fake.user_name()

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

def test_pattern_against_rules(pattern, static_data, rules):
    """Проверка паттерна против правил"""
    # Генерируем несколько примеров для паттерна
    examples = []
    for _ in range(10):
        example = replace_placeholders(pattern, static_data)
        example = example.replace('\n', '').replace('\r', '')
        examples.append(example)
    
    # Проверяем каждый пример против всех правил
    matching_rules = set()
    for example in examples:
        for rule_id, rule_data in rules.items():
            if rule_data['pattern'].search(example):
                matching_rules.add(rule_id)
    
    return matching_rules

def filter_patterns_by_rules(patterns, static_data, rules):
    """Фильтрация паттернов по правилам"""
    filtered_patterns = {}
    pattern_to_rules = {}
    
    print("Проверка паттернов против правил...")
    
    for category, pattern_list in patterns.items():
        filtered_patterns[category] = []
        
        for pattern in pattern_list:
            matching_rules = test_pattern_against_rules(pattern, static_data, rules)
            
            if matching_rules:
                filtered_patterns[category].append(pattern)
                pattern_to_rules[pattern] = matching_rules
                #print(f"✓ Паттерн '{pattern[:50]}...' соответствует правилам: {matching_rules}")
            else:
                print(f"✗ Паттерн '{pattern[:50]}...' НЕ соответствует ни одному правилу - удаляется")
    
    # Удаляем пустые категории
    filtered_patterns = {k: v for k, v in filtered_patterns.items() if v}
    
    return filtered_patterns, pattern_to_rules

def create_balanced_pattern_list(pattern_to_rules, rules, target_count):
    """Создание сбалансированного списка паттернов"""
    # Группируем паттерны по правилам
    rule_to_patterns = defaultdict(list)
    for pattern, matching_rules in pattern_to_rules.items():
        for rule_id in matching_rules:
            rule_to_patterns[rule_id].append(pattern)
    
    # Вычисляем количество секретов на правило
    num_rules = len(rule_to_patterns)
    secrets_per_rule = target_count // num_rules
    remainder = target_count % num_rules
    
    balanced_patterns = []
    rule_counts = {}
    
    for i, (rule_id, patterns) in enumerate(rule_to_patterns.items()):
        count = secrets_per_rule + (1 if i < remainder else 0)
        rule_counts[rule_id] = count
        
        # Равномерно распределяем паттерны для этого правила
        patterns_for_rule = []
        for j in range(count):
            pattern = patterns[j % len(patterns)]
            patterns_for_rule.append(pattern)
        
        balanced_patterns.extend(patterns_for_rule)
    
    return balanced_patterns, rule_counts

def analyze_dataset_against_rules(dataset_file, rules):
    """Анализ датасета против правил"""
    print(f"\nАнализ датасета {dataset_file}...")
    
    rule_matches = defaultdict(int)
    total_secrets = 0
    
    with open(dataset_file, 'r', encoding='utf-8') as f:
        for line in tqdm(f, desc="Анализ датасета"):
            line = line.strip()
            if not line:
                continue
                
            total_secrets += 1
            
            # Проверяем против каждого правила
            for rule_id, rule_data in rules.items():
                if rule_data['pattern'].search(line):
                    rule_matches[rule_id] += 1
    
    return rule_matches, total_secrets

def generate_secrets():
    """Основная функция генерации секретов"""
    # Создаем backup файла паттернов
    backup_file = f"{PATTERNS_FILE}.backup"
    if os.path.exists(PATTERNS_FILE):
        shutil.copy2(PATTERNS_FILE, backup_file)
        print(f"Создан backup файла: {backup_file}")
    
    # Загрузка конфигурации
    try:
        patterns = load_yaml_file(PATTERNS_FILE)
        static_data = load_yaml_file(STATIC_DATA_FILE)
        rules = load_rules()
        
        print(f"Загружено правил: {len(rules)}")
        print(f"Загружено категорий паттернов: {len(patterns)}")
        
        # Фильтрация паттернов по правилам
        filtered_patterns, pattern_to_rules = filter_patterns_by_rules(patterns, static_data, rules)
        
        # Сохраняем отфильтрованные паттерны
        save_yaml_file(PATTERNS_FILE, filtered_patterns)
        print(f"Сохранены отфильтрованные паттерны в {PATTERNS_FILE}")
        
        # Создаем список всех паттернов для анализа
        all_patterns = []
        for category, pattern_list in filtered_patterns.items():
            all_patterns.extend(pattern_list)
        
        if not all_patterns:
            print("Ошибка: Нет паттернов, соответствующих правилам!")
            return
        
        # Создаем сбалансированный список паттернов
        balanced_patterns, expected_rule_counts = create_balanced_pattern_list(
            pattern_to_rules, rules, N
        )
        
        print(f"\nОжидаемое распределение секретов по правилам:")
        for rule_id, count in expected_rule_counts.items():
            rule_message = rules[rule_id]['message']
            print(f"  {rule_id} ({rule_message}): {count}")
        
        # Генерация секретов
        secrets = []
        
        for i in tqdm(range(N), desc="Генерация секретов"):
            pattern = balanced_patterns[i]
            secret = replace_placeholders(pattern, static_data)
            # Удаляем переносы строк
            secret = secret.replace('\n', '').replace('\r', '')
            secrets.append(secret)
        
        # Запись в файл
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for secret in secrets:
                f.write(secret + '\n')
        
        print(f"\nСгенерировано {len(secrets)} секретов в файле {OUTPUT_FILE}")
        
        # Анализ результата
        rule_matches, total_secrets = analyze_dataset_against_rules(OUTPUT_FILE, rules)
        
        print(f"\nАнализ сгенерированного датасета:")
        print(f"Всего секретов: {total_secrets}")
        print(f"Распределение по правилам:")
        
        for rule_id, rule_data in rules.items():
            count = rule_matches.get(rule_id, 0)
            percentage = (count / total_secrets * 100) if total_secrets > 0 else 0
            expected = expected_rule_counts.get(rule_id, 0)
            print(f"  {rule_id} ({rule_data['message']}): {count} ({percentage:.1f}%) [ожидалось: {expected}]")
        
        # Проверка на несоответствие правилам
        unmatched = total_secrets - sum(rule_matches.values())
        if unmatched > 0:
            print(f"  Секретов, не соответствующих правилам: {unmatched}")
        
    except Exception as e:
        print(f"Ошибка: {e}")
        # Восстанавливаем backup в случае ошибки
        if os.path.exists(backup_file):
            shutil.copy2(backup_file, PATTERNS_FILE)
            print(f"Восстановлен файл из backup: {backup_file}")

if __name__ == "__main__":
    generate_secrets()