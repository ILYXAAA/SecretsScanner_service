import os
import asyncio
import yaml
import re
from app.model_loader import get_model_instance
import aiohttp
from concurrent.futures import ThreadPoolExecutor

with open('Settings/excluded_files.yml', 'r') as f:
    data = yaml.safe_load(f)

EXCLUDED_FILES = set(data.get('excluded_files', []))

with open('Settings/excluded_extensions.yml', 'r') as f:
    data = yaml.safe_load(f)

EXCLUDED_EXTENSIONS = set(data.get('excluded_extensions', []))

with open('Settings/false-positive.yml', 'r') as f:
    data = yaml.safe_load(f)

FALSE_POSITIVE_RULES = set(data.get('false_positive', []))

RULES_FILE = "Settings/rules.yml"

def load_rules(rules_file="Settings/rules.yml"):
    try:
        with open(rules_file, "r", encoding="UTF-8") as f:
            return yaml.safe_load(f)
    except Exception as error:
        print(f"Error: {str(error)} Проверьте, существует ли файл ${rules_file}$ с набором правил.")

def count_files(target_dir):
    count = 0
    for root, _, files in os.walk(target_dir):
        count += len(files)
    return count

def check_false_positive(secret, context):
    """True если секрет ложный"""  
    context_lower = context.lower()
    return any(pattern in context_lower for pattern.lower() in FALSE_POSITIVE_RULES)

async def _analyze_file(file_path, rules, target_dir, max_secrets=200, max_line_length=3000):
    """Асинхронная функция для анализа файла с ограничениями"""
    results = []
    secrets_found = 0
    
    try:
        with open(file_path, "r", encoding="UTF-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            if secrets_found >= max_secrets:
                results = []
                results.append({
                    "path": file_path.replace(target_dir, "").replace("\\", "/"),
                    "line": line_num,
                    "secret": f"ФАЙЛ НЕ СКАНИРОВАЛСЯ ПОЛНОСТЬЮ т.к. при анализе выявлено более {max_secrets} секретов. Проверьте файл вручную",
                    "context": f"Прервано на строке {line_num}. Найдено секретов: {secrets_found}",
                    "severity": "High",
                    "Type": "Too Many Secrets"
                })
                print(f"🛑 Прервано сканирование {file_path} - найдено более {max_secrets} секретов")
                break
            
            if len(line) > max_line_length:
                results.append({
                    "path": file_path.replace(target_dir, "").replace("\\", "/"),
                    "line": line_num,
                    "secret": f"СТРОКА НЕ СКАНИРОВАЛАСЬ т.к. её длина более {max_line_length} символов. Проверьте строку вручную",
                    "context": f"Строка {line_num} содержит большое количество символов. Длина более {max_line_length}.",
                    "severity": "Potential",
                    "Type": "Too Long Line"
                })
                continue
            
            for rule in rules:
                match = re.search(rule["pattern"], line)
                if match:
                    secret = match.group(0)
                    context = line.strip()
                    if not check_false_positive(secret, context):
                        results.append({
                            "path": file_path.replace(target_dir, "").replace("\\", "/"),
                            "line": line_num,
                            "secret": secret,
                            "context": context,
                            "severity": "",
                            "Type": rule.get("message", "Unknown")
                        })
                        secrets_found += 1
                    
                    if secrets_found >= max_secrets:
                        break
                        
    except Exception as error:
        print(f"❌ Error: {str(error)} — ошибка при обработке {file_path}")
    
    return results

async def search_secrets(file_path, rules, target_dir, max_secrets=200, max_line_length=3000):
    """Простая обертка для анализа файла"""
    return await _analyze_file(file_path, rules, target_dir, max_secrets, max_line_length)

async def scan_directory(request, target_dir, rules):
    """Сканирование директории с отправкой промежуточных результатов"""
    all_results = []
    file_list = []

    # Собираем список файлов для обработки
    for root, _, files in os.walk(target_dir):
        for file in files:           
            file_ext = file.split(".")[-1].lower()
            if file_ext in EXCLUDED_EXTENSIONS or file in EXCLUDED_FILES:
                continue
            file_list.append(os.path.join(root, file))

    print(f"📁 Найдено файлов для сканирования: {len(file_list)}")
    
    SEND_PARTIAL_EVERY = max(1, len(file_list) // 10)
    
    # Process files concurrently in batches
    batch_size = 5
    for i in range(0, len(file_list), batch_size):
        batch = file_list[i:i + batch_size]
        
        # Process batch concurrently
        batch_tasks = [
            search_secrets(file_path, rules, target_dir, max_secrets=200, max_line_length=3000)
            for file_path in batch
        ]
        
        batch_results = await asyncio.gather(*batch_tasks)
        
        # Collect results
        for results in batch_results:
            all_results.extend(results)
        
        # Send partial results
        if (i + batch_size) % SEND_PARTIAL_EVERY == 0:
            payload = {
                "Status": "partial",
                "FilesScanned": i + batch_size
            }
            
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    await session.post(request.CallbackUrl, json=payload)
                print(f"📊 Отправлен промежуточный результат: {i + batch_size}/{len(file_list)}")
            except Exception as e:
                print(f"⚠️ Ошибка отправки промежуточного результата: {e}")

    print(f"✅ Сканирование завершено. Обработано файлов: {len(file_list)}")
    return all_results, len(file_list)

async def scan_directory_without_callback(target_dir, rules):
    """Сканирование директории без callback (для использования в процессах)"""
    all_results = []
    file_list = []

    for root, _, files in os.walk(target_dir):
        for file in files:           
            file_ext = file.split(".")[-1].lower()
            if file_ext in EXCLUDED_EXTENSIONS or file in EXCLUDED_FILES:
                continue
            file_list.append(os.path.join(root, file))

    print(f"📁 Найдено файлов для сканирования: {len(file_list)}")
    
    # Process files concurrently in batches
    batch_size = 5
    for i in range(0, len(file_list), batch_size):
        batch = file_list[i:i + batch_size]
        
        batch_tasks = [
            search_secrets(file_path, rules, target_dir, max_secrets=200, max_line_length=3000)
            for file_path in batch
        ]
        
        batch_results = await asyncio.gather(*batch_tasks)
        
        for results in batch_results:
            all_results.extend(results)

    print(f"✅ Сканирование завершено. Обработано файлов: {len(file_list)}")
    return all_results, len(file_list)

async def scan_repo(request, repo_path, projectName):
    """Основная функция сканирования с callback"""
    model = get_model_instance()
    rules = load_rules(RULES_FILE)
    print(f"✅ Начинаю сканирование {projectName}")
    results, all_files_count = await scan_directory(request, repo_path, rules)
    print("ДИРЕКТОРИЯ ПРОСКАНИРОВАНА НАЧИНАЮ ВАЛИДАЦИЮ")
    sevveritied_secrets = model.filter_secrets(results)
    return sevveritied_secrets, all_files_count

async def scan_repo_without_callback(request, repo_path, projectName):
    """Сканирование без callback для использования в отдельных процессах"""
    rules = load_rules(RULES_FILE)
    print(f"✅ Начинаю сканирование {projectName}")
    results, all_files_count = await scan_directory_without_callback(repo_path, rules)
    print("ДИРЕКТОРИЯ ПРОСКАНИРОВАНА")
    return results, all_files_count