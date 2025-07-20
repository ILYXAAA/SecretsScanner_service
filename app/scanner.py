import os
import asyncio
import yaml
import re
from app.model_loader import get_model_instance
import aiohttp
import hashlib
import time
import fnmatch
import json
import logging
from logging.handlers import RotatingFileHandler

# Setup logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('secrets_scanner_service.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()  # Также выводить в консоль
    ]
)
logger = logging.getLogger("scanner")

RULES_FILE = "Settings/rules.yml"

def load_rules(rules_file="Settings/rules.yml"):
    try:
        with open(rules_file, "r", encoding="UTF-8") as f:
            return yaml.safe_load(f)
    except Exception as error:
        logger.error(f"Error: {str(error)} Проверьте, существует ли файл ${rules_file}$ с набором правил.")

def load_other_rules():
    with open('Settings/excluded_files.yml', 'r') as f:
        data = yaml.safe_load(f)

    EXCLUDED_FILES = set(data.get('excluded_files', []))

    with open('Settings/excluded_extensions.yml', 'r') as f:
        data = yaml.safe_load(f)

    EXCLUDED_EXTENSIONS = set(data.get('excluded_extensions', []))

    with open('Settings/false-positive.yml', 'r') as f:
        data = yaml.safe_load(f)

    FALSE_POSITIVE_RULES = set(data.get('false_positive', []))

    return EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES

def load_languages_patterns():
    """Загружает паттерны языков из JSON файла"""
    try:
        with open('Settings/languages_patterns.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка загрузки языковых паттернов: {e}")
        return {}

def load_frameworks_rules():
    """Загружает правила определения фреймворков"""
    try:
        with open('Settings/frameworks_detection.yml', 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Ошибка загрузки правил фреймворков: {e}")
        return {}

def check_code_patterns_exists(file_path, patterns):
    """Проверяет наличие паттернов в коде (возвращает True/False)"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    
    except Exception as e:
        logger.error(f"Ошибка при чтении кода {file_path}: {e}")
    
    return False

def format_framework_results(detections_dict):
    """Форматирует результаты в требуемый формат"""
    result = {}
    
    for framework_name, detections in detections_dict.items():
        framework_results = []
        
        # Манифесты
        manifest_files = list(detections["manifest"]["files"])
        if manifest_files:
            count = len(manifest_files)
            limited_files = manifest_files[:100]
            dependencies_str = ", ".join(sorted(detections["manifest"]["dependencies"]))
            
            if count > 100:
                description = f"В 100+ манифестах найдена зависимость {framework_name} ({dependencies_str})"
            else:
                description = f"В {count} манифестах найдена зависимость {framework_name} ({dependencies_str})"
            
            framework_results.append({
                "Description": description,
                "Files": limited_files
            })
        
        # Файлы конфигурации
        config_files = list(detections["config_file"])
        if config_files:
            count = len(config_files)
            limited_files = config_files[:100]
            
            if count > 100:
                description = f"Найдено 100+ файлов конфигурации {framework_name}"
            else:
                description = f"Найдено {count} файлов конфигурации {framework_name}"
            
            framework_results.append({
                "Description": description,
                "Files": limited_files
            })
        
        # Упоминания в коде
        code_files = list(detections["code"])
        if code_files:
            count = len(code_files)
            limited_files = code_files[:100]
            
            if count > 100:
                description = f"В 100+ файлах найдено упоминание {framework_name}"
            else:
                description = f"В {count} файлах найдено упоминание {framework_name}"
            
            framework_results.append({
                "Description": description,
                "Files": limited_files
            })
        
        if framework_results:
            result[framework_name] = framework_results
    
    return result

def detect_languages(target_dir):
    """Определяет языки программирования в директории"""
    languages_patterns = load_languages_patterns()
    if not languages_patterns:
        return {}
    
    # Создаем словарь расширение -> язык для быстрого поиска
    extension_to_language = {}
    for language, data in languages_patterns.items():
        for ext in data.get('extensions', []):
            extension_to_language[ext.lower()] = language
    
    detected_languages = {}
    
    for root, _, files in os.walk(target_dir):
        for file in files:
            file_ext = get_full_extension(file)
            
            if file_ext in extension_to_language:
                language = extension_to_language[file_ext]
            else:
                language = "Other"
            
            if language not in detected_languages:
                detected_languages[language] = {
                    "Files": 0,
                    "ExtensionsList": set()
                }
            
            detected_languages[language]["Files"] += 1
            detected_languages[language]["ExtensionsList"].add(file_ext)
    
    # Конвертируем set в list для JSON сериализации
    for language_data in detected_languages.values():
        language_data["ExtensionsList"] = sorted(list(language_data["ExtensionsList"]))
    
    # Убираем пустые результаты
    return {k: v for k, v in detected_languages.items() if v["Files"] > 0}

def add_framework_detection(detections_dict, framework_name, detection_type, file_path, dependencies=None):
    """Добавляет обнаружение фреймворка в словарь"""
    if framework_name not in detections_dict:
        detections_dict[framework_name] = {
            "manifest": {"files": set(), "dependencies": set()},
            "config_file": set(),
            "code": set()
        }
    
    if detection_type == "manifest":
        detections_dict[framework_name]["manifest"]["files"].add(file_path)
        if dependencies:
            detections_dict[framework_name]["manifest"]["dependencies"].update(dependencies)
    elif detection_type == "config_file":
        detections_dict[framework_name]["config_file"].add(file_path)
    elif detection_type == "code":
        detections_dict[framework_name]["code"].add(file_path)

def detect_frameworks(target_dir):
    """Определяет используемые фреймворки в проекте"""
    frameworks_rules = load_frameworks_rules()
    if not frameworks_rules:
        return {}
    
    frameworks = frameworks_rules.get('frameworks', {})
    manifest_files = frameworks_rules.get('manifest_files', [])
    
    # Словарь для группировки результатов по типам
    framework_detections = {}
    
    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = file_path.replace(target_dir, "").replace("\\", "/").lstrip("/")
            
            # Проверка манифест-файлов
            if file in manifest_files:
                manifest_results = check_manifest_dependencies(file_path, relative_path, frameworks)
                for framework_name, dependencies in manifest_results.items():
                    # Проверяем лимит для манифестов
                    if framework_name not in framework_detections:
                        framework_detections[framework_name] = {
                            "manifest": {"files": set(), "dependencies": set()},
                            "config_file": set(),
                            "code": set()
                        }
                    
                    if len(framework_detections[framework_name]["manifest"]["files"]) < 101:
                        add_framework_detection(framework_detections, framework_name, "manifest", relative_path, dependencies)
            
            # Проверка специфичных файлов фреймворков
            for framework_name, rules in frameworks.items():
                if file in rules.get('files', []):
                    if framework_name not in framework_detections:
                        framework_detections[framework_name] = {
                            "manifest": {"files": set(), "dependencies": set()},
                            "config_file": set(),
                            "code": set()
                        }
                    
                    if len(framework_detections[framework_name]["config_file"]) < 101:
                        add_framework_detection(framework_detections, framework_name, "config_file", relative_path)
            
            # Проверка упоминаний в коде
            file_ext = get_full_extension(file)
            for framework_name, rules in frameworks.items():
                code_extensions = rules.get('code_extensions', [])
                if file_ext in code_extensions:
                    if framework_name not in framework_detections:
                        framework_detections[framework_name] = {
                            "manifest": {"files": set(), "dependencies": set()},
                            "config_file": set(),
                            "code": set()
                        }
                    
                    if len(framework_detections[framework_name]["code"]) < 101:
                        if check_code_patterns_exists(file_path, rules.get('code_patterns', [])):
                            add_framework_detection(framework_detections, framework_name, "code", relative_path)
    
    # Форматируем результат
    return format_framework_results(framework_detections)
def check_manifest_dependencies(file_path, relative_path, frameworks):
    """Проверяет зависимости в манифест-файлах"""
    detected = {}
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        for framework_name, rules in frameworks.items():
            dependencies = rules.get('dependencies', [])
            found_dependencies = []
            for dependency in dependencies:
                if dependency in content:
                    found_dependencies.append(dependency)
            
            if found_dependencies:
                detected[framework_name] = found_dependencies
    
    except Exception as e:
        logger.error(f"Ошибка при чтении манифеста {file_path}: {e}")
    
    return detected

def check_code_patterns(file_path, relative_path, framework_name, patterns):
    """Проверяет паттерны в коде"""
    found_patterns = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.add(pattern)
    
    except Exception as e:
        logger.error(f"Ошибка при чтении кода {file_path}: {e}")
    
    # Возвращаем одну запись на файл, если найдены паттерны
    if found_patterns:
        return [{
            "Description": f"В файле найдено упоминание {framework_name}",
            "File": relative_path
        }]
    
    return []

def merge_framework_detections(target_dict, source_dict):
    """Объединяет результаты определения фреймворков, избегая дубликатов по файлам"""
    for framework_name, detections in source_dict.items():
        if framework_name not in target_dict:
            target_dict[framework_name] = []
        
        # Получаем уже существующие файлы для этого фреймворка
        existing_files = {item["File"] for item in target_dict[framework_name]}
        
        # Добавляем только новые файлы
        for detection in detections:
            if detection["File"] not in existing_files:
                target_dict[framework_name].append(detection)
                existing_files.add(detection["File"])

def count_files(target_dir):
    count = 0
    for root, _, files in os.walk(target_dir):
        count += len(files)
    return count

def check_false_positive(secret, context, FALSE_POSITIVE_RULES):
    """True если секрет ложный"""
    context_lower = context.lower()
    return any(pattern.lower() in context_lower for pattern in FALSE_POSITIVE_RULES)

def get_full_extension(filename):
    return os.path.splitext(filename)[1].lower()

def is_extension_excluded(file_ext, EXCLUDED_EXTENSIONS):
    if file_ext in EXCLUDED_EXTENSIONS:
        #logger.info(f"file_ext: {file_ext} in EXCLUDED_EXTENSIONS - True")
        return True
    return False
    # for pattern in EXCLUDED_EXTENSIONS:
    #     if fnmatch.fnmatch(file_ext, pattern):
    #         logger.info(f"file_ext: {file_ext}, pattern: {pattern} - True")
    #         return True
    # return False

async def _analyze_file(file_path, rules, target_dir, max_secrets=50, max_line_length=15_000, FALSE_POSITIVE_RULES=[]):
    """Асинхронная функция для анализа файла с ограничениями"""
    results = []
    all_secrets = []
    secrets_found = 0

    try:
        with open(file_path, "r", encoding="UTF-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            if len(line) > max_line_length:
                hashed_line = hashlib.md5(line.encode('utf-8')).hexdigest()
                results.append({
                    "path": file_path.replace(target_dir, "").replace("\\", "/"),
                    "line": line_num,
                    "secret": f"СТРОКА НЕ СКАНИРОВАЛАСЬ т.к. её длина более {max_line_length} символов. Проверьте строку вручную. Хеш строки: {hashed_line}",
                    "context": f"Строка {line_num} содержит большое количество символов. Длина: {len(line)}.",
                    "severity": "Potential",
                    "Type": "Too Long Line"
                })
                continue

            for rule in rules:
                match = re.search(rule["pattern"], line)
                if match:
                    secret = match.group(0)
                    context = line.strip()
                    if not check_false_positive(secret, context, FALSE_POSITIVE_RULES):
                        all_secrets.append({
                            "path": file_path.replace(target_dir, "").replace("\\", "/"),
                            "line": line_num,
                            "secret": secret,
                            "context": context,
                            "severity": "",
                            "confidence": 1.0,
                            "Type": rule.get("message", "Unknown")
                        })
                        secrets_found += 1

        if secrets_found > max_secrets:
            all_secrets_string = "\n".join([s["secret"] for s in all_secrets])
            hashed_secrets = hashlib.md5(all_secrets_string.encode('utf-8')).hexdigest()
            results = [{
                "path": file_path.replace(target_dir, "").replace("\\", "/"),
                "line": 0,
                "secret": f"ФАЙЛ НЕ ВЫВЕДЕН ПОЛНОСТЬЮ т.к. найдено более {max_secrets} секретов. Проверьте файл вручную. Хеш всех секретов: {hashed_secrets}",
                "context": f"Найдено секретов: {secrets_found}\nСписок найденных секретов ниже:\n{all_secrets_string}",
                "severity": "High",
                "Type": "Too Many Secrets"
            }]
        else:
            results.extend(all_secrets)

    except Exception as error:
        logger.error(f"Error: {str(error)} — ошибка при обработке {file_path}")

    return results


async def search_secrets(file_path, rules, target_dir, max_secrets=50, max_line_length=15_000, FALSE_POSITIVE_RULES=[]):
    """Простая обертка для анализа файла"""
    return await _analyze_file(file_path, rules, target_dir, max_secrets, max_line_length, FALSE_POSITIVE_RULES)


async def scan_directory_without_callback(projectName, target_dir, rules, EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES):
    """Сканирование директории без callback (для использования в процессах)"""
    scan_start = time.time()
    all_results = []
    file_list = []
    all_files_count = 0
    skipped_extensions = []
    skipped_files = []

    # Сбор файлов
    file_collection_start = time.time()
    for root, _, files in os.walk(target_dir):
        for file in files:
            all_files_count += 1
            file_ext = get_full_extension(file)
            if is_extension_excluded(file_ext, EXCLUDED_EXTENSIONS):
                skipped_extensions.append(file_ext)
                if f"*{file_ext}" not in skipped_files:
                    skipped_files.append(f"*{file_ext}")
                continue
            elif file in EXCLUDED_FILES:
                if file not in skipped_files:
                    skipped_files.append(file)
                continue
            file_list.append(os.path.join(root, file))

    file_collection_time = time.time() - file_collection_start
    logger.info(f"[{projectName}] Найдено файлов для сканирования: {len(file_list)} (время сбора: {file_collection_time:.2f}с)")
    logger.info(f"[{projectName}] Пропущены файлы (by rules): {skipped_files}")
    
    # Process files concurrently in batches
    batch_size = 5
    for i in range(0, len(file_list), batch_size):
        batch = file_list[i:i + batch_size]
        
        batch_tasks = [
            search_secrets(file_path, rules, target_dir, max_secrets=50, max_line_length=15_000, FALSE_POSITIVE_RULES=FALSE_POSITIVE_RULES)
            for file_path in batch
        ]
        
        batch_results = await asyncio.gather(*batch_tasks)
        
        for results in batch_results:
            all_results.extend(results)

    # Определение языков программирования
    languages_start = time.time()
    detected_languages = detect_languages(target_dir)
    languages_time = time.time() - languages_start
    logger.info(f"[{projectName}] Определение языков завершено (время: {languages_time:.2f}с)")

    # Определение фреймворков
    frameworks_start = time.time()
    detected_frameworks = detect_frameworks(target_dir)
    frameworks_time = time.time() - frameworks_start
    logger.info(f"[{projectName}] Определение фреймворков завершено (время: {frameworks_time:.2f}с)")

    total_scan_time = time.time() - scan_start
    logger.info(f"[{projectName}] Сканирование завершено. Обработано файлов: {len(file_list)}, найдено секретов: {len(all_results)} (общее время: {total_scan_time:.2f}с)")
    files_excluded = all_files_count - len(file_list)
    skipped_files = ", ".join(skipped_files)
    
    return all_results, files_excluded, all_files_count, skipped_files, detected_languages, detected_frameworks

async def scan_repo_without_callback(request, repo_path, projectName):
    """Сканирование без callback для использования в отдельных процессах"""
    scan_start = time.time()
    
    rules = load_rules(RULES_FILE)
    EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES = load_other_rules()
    
    logger.info(f"[{projectName}] Начинаю сканирование")
    
    results, files_excluded, all_files_count, skipped_files, detected_languages, detected_frameworks = await scan_directory_without_callback(projectName, repo_path, rules, EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES)
    
    total_time = time.time() - scan_start
    logger.info(f"[{projectName}] Сканирование завершено (общее время: {total_time:.2f}с)")
    
    return results, files_excluded, all_files_count, skipped_files, detected_languages, detected_frameworks