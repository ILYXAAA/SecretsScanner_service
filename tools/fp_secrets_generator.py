#!/usr/bin/env python3
import yaml
import random
import string
import uuid
import re
from datetime import datetime, timedelta
from faker import Faker
from tqdm import tqdm
from collections import defaultdict

fake = Faker()

# Константы
N = 70_000
OUTPUT_FILE = "Dataset_NonSecrets.txt"
RULES_FILE = "../Settings/rules.yml"

def load_yaml_file(filename):
    """Загрузка YAML файла"""
    with open(filename, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

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

def generate_app_name():
    """Генерация названия приложения"""
    apps = [
        "MyApp", "WebService", "MobileApp", "DataProcessor", "ApiGateway",
        "UserService", "PaymentService", "NotificationService", "AuthService",
        "LoggingService", "MonitoringTool", "Dashboard", "Analytics"
    ]
    return random.choice(apps)

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
        'OS_VERSION': generate_os_version,
        'APP_NAME': generate_app_name,
    }
    
    return generators.get(value_type, lambda: generate_random_string(10))()

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
    try:
        # Загрузка конфигурации
        patterns = load_yaml_file('non_secrets_patterns.yaml')
        static_data = load_yaml_file('non_secrets_static_data.yaml')
        rules = load_rules()
        
        print(f"Загружено правил: {len(rules)}")
        print(f"Загружено категорий паттернов: {len(patterns)}")
        
        # Фильтрация паттернов по правилам
        filtered_patterns, pattern_to_rules = filter_patterns_by_rules(patterns, static_data, rules)
        
        # Создание списка всех паттернов
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
        
        print(f"\nОжидаемое распределение НЕ-секретов по правилам:")
        for rule_id, count in expected_rule_counts.items():
            rule_message = rules[rule_id]['message']
            print(f"  {rule_id} ({rule_message}): {count}")
        
        # Генерация НЕ-секретов
        non_secrets = []
        
        for i in tqdm(range(N), desc="Генерация НЕ-секретов"):
            pattern = balanced_patterns[i]
            non_secret = replace_placeholders(pattern, static_data)
            # Удаляем переносы строк
            non_secret = non_secret.replace('\n', '').replace('\r', '')
            non_secrets.append(non_secret)
        
        # Запись в файл
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for non_secret in non_secrets:
                f.write(non_secret + '\n')
        
        print(f"\nСгенерировано {len(non_secrets)} НЕ-секретов в файле {OUTPUT_FILE}")
        
        # Анализ результата
        rule_matches, total_secrets = analyze_dataset_against_rules(OUTPUT_FILE, rules)
        
        print(f"\nАнализ сгенерированного датасета НЕ-секретов:")
        print(f"Всего НЕ-секретов: {total_secrets}")
        print(f"Распределение по правилам:")
        
        for rule_id, rule_data in rules.items():
            count = rule_matches.get(rule_id, 0)
            percentage = (count / total_secrets * 100) if total_secrets > 0 else 0
            expected = expected_rule_counts.get(rule_id, 0)
            print(f"  {rule_id} ({rule_data['message']}): {count} ({percentage:.1f}%) [ожидалось: {expected}]")
        
        # Проверка на несоответствие правилам
        unmatched = total_secrets - sum(rule_matches.values())
        if unmatched > 0:
            print(f"  НЕ-секретов, не соответствующих правилам: {unmatched}")
            
    except Exception as e:
        print(f"Ошибка: {e}")

if __name__ == "__main__":
    generate_non_secrets()