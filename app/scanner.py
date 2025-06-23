import os
import asyncio
import yaml
import re
from app.model_loader import get_model_instance
import aiohttp
import hashlib
import time
import fnmatch
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
    match = re.search(r'(\.[^.]+){1,2}$', filename)
    return match.group(0).lower() if match else ''

def is_extension_excluded(file_ext, EXCLUDED_EXTENSIONS):
    for pattern in EXCLUDED_EXTENSIONS:
        if fnmatch.fnmatch(file_ext, pattern):
            return True
    return False

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

async def scan_directory(request, target_dir, rules, EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES):
    """Сканирование директории с отправкой промежуточных результатов"""
    scan_start = time.time()
    all_results = []
    file_list = []

    # Собираем список файлов для обработки
    file_collection_start = time.time()
    for root, _, files in os.walk(target_dir):
        for file in files:           
            file_ext = get_full_extension(file)
            if is_extension_excluded(file_ext, EXCLUDED_EXTENSIONS) or file in EXCLUDED_FILES:
                continue
            if file_ext in EXCLUDED_EXTENSIONS or file in EXCLUDED_FILES:
                continue
            file_list.append(os.path.join(root, file))

    file_collection_time = time.time() - file_collection_start
    logger.info(f"Найдено файлов для сканирования: {len(file_list)} (время сбора: {file_collection_time:.2f}с)")
    
    SEND_PARTIAL_EVERY = max(1, len(file_list) // 10)
    
    # Process files concurrently in batches
    batch_size = 5
    files_processed = 0
    for i in range(0, len(file_list), batch_size):
        batch_start = time.time()
        batch = file_list[i:i + batch_size]
        
        # Process batch concurrently
        batch_tasks = [
            search_secrets(file_path, rules, target_dir, max_secrets=50, max_line_length=15_000, FALSE_POSITIVE_RULES=FALSE_POSITIVE_RULES)
            for file_path in batch
        ]
        
        batch_results = await asyncio.gather(*batch_tasks)
        
        # Collect results
        for results in batch_results:
            all_results.extend(results)
        
        files_processed += len(batch)
        batch_time = time.time() - batch_start
        
        # Send partial results
        if files_processed % SEND_PARTIAL_EVERY == 0:
            payload = {
                "Status": "partial",
                "FilesScanned": files_processed
            }
            
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    await session.post(request.CallbackUrl, json=payload)
                logger.info(f"Отправлен промежуточный результат: {files_processed}/{len(file_list)} (batch время: {batch_time:.2f}с)")
            except Exception as e:
                logger.warning(f"Ошибка отправки промежуточного результата: {e}")

    total_scan_time = time.time() - scan_start
    logger.info(f"Сканирование завершено. Обработано файлов: {len(file_list)}, найдено секретов: {len(all_results)} (общее время: {total_scan_time:.2f}с)")
    return all_results, len(file_list)

async def scan_directory_without_callback(target_dir, rules, EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES):
    """Сканирование директории без callback (для использования в процессах)"""
    scan_start = time.time()
    all_results = []
    file_list = []

    # Сбор файлов
    file_collection_start = time.time()
    for root, _, files in os.walk(target_dir):
        for file in files:           
            file_ext = get_full_extension(file)
            if is_extension_excluded(file_ext, EXCLUDED_EXTENSIONS) or file in EXCLUDED_FILES:
                continue
            file_list.append(os.path.join(root, file))

    file_collection_time = time.time() - file_collection_start
    logger.info(f"Найдено файлов для сканирования: {len(file_list)} (время сбора: {file_collection_time:.2f}с)")
    
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

    total_scan_time = time.time() - scan_start
    logger.info(f"Сканирование завершено. Обработано файлов: {len(file_list)}, найдено секретов: {len(all_results)} (общее время: {total_scan_time:.2f}с)")
    return all_results, len(file_list)

async def scan_repo(request, repo_path, projectName):
    """Основная функция сканирования с callback"""
    total_start = time.time()
    
    model_load_start = time.time()
    model = get_model_instance()
    model_load_time = time.time() - model_load_start
    
    rules = load_rules(RULES_FILE)
    EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES = load_other_rules()
    
    logger.info(f"Начинаю сканирование {projectName} (загрузка модели: {model_load_time:.2f}с)")
    
    results, all_files_count = await scan_directory(request, repo_path, rules, EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES)
    
    validation_start = time.time()
    logger.info("ДИРЕКТОРИЯ ПРОСКАНИРОВАНА, НАЧИНАЮ ВАЛИДАЦИЮ")
    sevveritied_secrets = model.filter_secrets(results)
    validation_time = time.time() - validation_start
    
    total_time = time.time() - total_start
    logger.info(f"Сканирование {projectName} завершено (валидация: {validation_time:.2f}с, общее время: {total_time:.2f}с)")
    
    return sevveritied_secrets, all_files_count

async def scan_repo_without_callback(request, repo_path, projectName):
    """Сканирование без callback для использования в отдельных процессах"""
    scan_start = time.time()
    
    rules = load_rules(RULES_FILE)
    EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES = load_other_rules()
    
    logger.info(f"Начинаю сканирование {projectName}")
    
    results, all_files_count = await scan_directory_without_callback(repo_path, rules, EXCLUDED_FILES, EXCLUDED_EXTENSIONS, FALSE_POSITIVE_RULES)
    
    total_time = time.time() - scan_start
    logger.info(f"Сканирование {projectName} без callback завершено (общее время: {total_time:.2f}с)")
    
    return results, all_files_count