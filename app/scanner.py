import os
import asyncio
import yaml
import re
from app.model_loader import get_model_instance
import aiohttp
from concurrent.futures import ThreadPoolExecutor

with open('Settings/excluded_files.yml', 'r') as f:
    data = yaml.safe_load(f)

# Преобразуем список в множество
EXCLUDED_FILES = set(data.get('excluded_files', []))

with open('Settings/excluded_extensions.yml', 'r') as f:
    data = yaml.safe_load(f)

# Преобразуем список в множество
EXCLUDED_EXTENSIONS = set(data.get('excluded_extensions', []))

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

def check_false_positive(secret, context): # True если секрет фолза
    if 'token cancellationtoken' in context.lower():
        return True
    if 'sha512' in context.lower():
        return True
    if 'sha256' in context.lower():
        return True
    if 'password = null' in context.lower():
        return True
    if '{env.' in context.lower():
        return True
    if 'passwordsdonotmatchexception' in context.lower():
        return True
    if 'passwordexception' in context.lower():
        return True
    if 'CRED_ID' in context:
        return True
    if '"png' in context:
        return True
    if '"integrity' in context:
        return True
    if '"sha1' in context:
        return True
    if 'password) => {' in context:
        return True
    if 'credentials=None,' in context:
        return True
    if 'password: ${' in context:
        return True
    if 'CRED_ID = ' in context:
        return True
    if 'CredentialStore>(store)' in context:
        return True
    if 'CredentialStore.' in context:
        return True
    if '=\"$.' in context:
        return True
    if '=CREDIT}' in context:
        return True
    if '<password>${' in context:
        return True
    if 'secretKeyRef:' in context:
        return True
    return False

async def _analyze_file(file_path, rules, target_dir, max_secrets=200, max_line_length=3000):
    """Асинхронная функция для анализа файла с ограничениями"""
    results = []
    secrets_found = 0
    
    try:
        with open(file_path, "r", encoding="UTF-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            # Проверяем лимит найденных секретов
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
            
            # Сканируем строку на предмет секретов
            for rule in rules:
                match = re.search(rule["pattern"], line)
                if match:
                    # Проверяем длину текущей строки
                    if len(line) > max_line_length:
                        results.append({
                            "path": file_path.replace(target_dir, "").replace("\\", "/"),
                            "line": line_num,
                            "secret": f"СТРОКА НЕ СКАНИРОВАЛАСЬ т.к. её длина более {max_line_length} символов. Проверьте строку вручную",
                            "context": f"Строка {line_num} содержит большое количество символов. Длина более {max_line_length}.",
                            "severity": "Potential",
                            "Type": "Too Long Line"
                        })
                        continue  # Пропускаем длинную строку
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
                    
                    # Проверяем лимит после каждого найденного секрета
                    if secrets_found >= max_secrets:
                        break
                        
    except Exception as error:
        print(f"❌ Error: {str(error)} — ошибка при обработке {file_path}")
    
    return results

async def search_secrets(file_path, rules, target_dir, max_secrets=200, max_line_length=3000):
    """Простая обертка для анализа файла"""
    return await _analyze_file(file_path, rules, target_dir, max_secrets, max_line_length)

async def scan_directory(request, target_dir, rules):
    all_results = []
    file_list = []
    all_files_count = 0

    # Собираем список файлов для обработки
    for root, _, files in os.walk(target_dir):
        for file in files:           
            file_ext = file.split(".")[-1].lower()
            if file_ext in EXCLUDED_EXTENSIONS or file in EXCLUDED_FILES:
                continue
            file_list.append(os.path.join(root, file))

    print(f"📁 Найдено файлов для сканирования: {len(file_list)}")
    
    SEND_PARTIAL_EVERY = max(1, len(file_list) // 10)
    
    for file_path in file_list:
        all_files_count += 1
        
        # Отправляем промежуточные результаты
        if all_files_count % SEND_PARTIAL_EVERY == 0:
            payload = {
                "Status": "partial",
                "FilesScanned": all_files_count
            }
            
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(request.CallbackUrl, json=payload)
                print(f"📊 Отправлен промежуточный результат: {all_files_count}/{len(file_list)}")
            except Exception as e:
                print(f"⚠️ Ошибка отправки промежуточного результата: {e}")
        
        # Обрабатываем файл с ограничениями
        print(f"🔍 Сканируем файл {all_files_count}/{len(file_list)}: {os.path.basename(file_path)}")
        
        results = await search_secrets(
            file_path, 
            rules, 
            target_dir, 
            max_secrets=200,      # максимум секретов в файле
            max_line_length=3000  # максимум символов в строке
        )
        all_results.extend(results)

    print(f"✅ Сканирование завершено. Обработано файлов: {all_files_count}")
    return all_results, all_files_count

async def scan_repo(request, repo_path, projectName):
    model = get_model_instance()
    rules = load_rules(RULES_FILE)
    print(f"✅ Начинаю сканирование {projectName}")
    results, all_files_count = await scan_directory(request, repo_path, rules)
    print("ДИРЕКТОРИЯ ПРОСКАНИРОВАНА НАЧИНАЮ ВАЛИДАЦИЮ")
    sevveritied_secrets = model.filter_secrets(results)

    return sevveritied_secrets, all_files_count



# async def scan_repo(repo_path): # path - Должно возвращать полный путь до файла в репе
#     results = []
#     all_files_count = 0
#     for root, _, files in os.walk(repo_path):
#         for f in files:
#             all_files_count += 1
#             if f.endswith(".txt"):
#                 path = os.path.join(root, f)
#                 try:
#                     with open(path, "r", encoding="utf-8") as file:
#                         for i, line in enumerate(file, 1):
#                             if "password" in line.lower():
#                                 normal_path = path.replace(repo_path, '').replace('\\', '/')
#                                 # full_path = f"{RepoUrl}/{tmp_str}"
#                                 # print(f"FILE: {normal_path}")
#                                 results.append({
#                                     "path": normal_path,
#                                     "line": i,
#                                     "secret": "password",
#                                     "context": line.strip(),
#                                     "severity": "High",
#                                     "Type": "PASSWORD"
#                                 })
#                 except:
#                     continue
#     print(f"Делаем вид что думаем 10 секунд")
#     await asyncio.sleep(10)
#     return results, all_files_count
