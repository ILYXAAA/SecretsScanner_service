import os
import asyncio
import yaml
import re
from app.model_loader import get_model_instance
import aiohttp

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

async def _analyze_file(file_path, rules, target_dir):
    results = []
    try:
        with open(file_path, "r", encoding="UTF-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            for rule in rules:
                match = re.search(rule["pattern"], line)
                if match:
                    secret = match.group(0)
                    context = line.strip()
                    results.append({
                        "path": file_path.replace(target_dir, "").replace("\\", "/"),
                        "line": line_num,
                        "secret": secret,
                        "context": context,
                        "severity": "",
                        "Type": rule.get("message", "Unknown")
                    })
    except Exception as error:
        print(f"❌ Error: {str(error)} — ошибка при обработке {file_path}")
    
    return results

async def search_secrets(file_path, rules, target_dir, timeout=60):  # timeout в секундах
    try:
        return await asyncio.wait_for(
            _analyze_file(file_path, rules, target_dir),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        results = []
        results.append({
                        "path": file_path.replace(target_dir, "").replace("\\", "/"),
                        "line": 0,
                        "secret": "ФАЙЛ НЕ СКАНИРОВАЛСЯ т.к. его анализ упал по таймауту. Проверьте файл вручную",
                        "context": "ФАЙЛ НЕ СКАНИРОВАЛСЯ т.к. его анализ упал по таймауту. Проверьте файл вручную",
                        "severity": "High",
                        "Type": "Unknown"
                    })
        print(f"⏱️ Пропущен файл из-за тайм-аута: {file_path}")
        return results

# async def search_secrets(file_path, rules, target_dir):
#     results = []
#     print(f"{file_path=}")
#     try:
#         with open(file_path, "r", encoding="UTF-8", errors="ignore") as f:
#             lines = f.readlines()

#         for line_num, line in enumerate(lines, start=1):
#             for rule in rules:
#                 match = re.search(rule["pattern"], line)
#                 if match:
#                     secret = match.group(0)
#                     context = line.strip()
#                     results.append({
#                         "path": file_path.replace(target_dir, "").replace("\\", "/"),
#                         "line": line_num,
#                         "secret": secret,
#                         "context": context,
#                         "severity": "",
#                         "Type": rule.get("message", "Unknown")
#                     })
#     except Exception as error:
#         print(f"Error: {str(error)} Ошибка при обработке ${file_path}$")
    
#     return results

async def scan_directory(request, target_dir, rules):
    all_results = []
    file_list = []
    all_files_count = 0

    for root, _, files in os.walk(target_dir):
        for file in files:           
            file_ext = file.split(".")[-1].lower()
            if file_ext in EXCLUDED_EXTENSIONS or file in EXCLUDED_FILES:
                continue
            file_list.append(os.path.join(root, file))

    SEND_PARTIAL_EVERY = max(1, len(file_list) // 10)
    for file_path in file_list:
        all_files_count += 1
        if all_files_count % SEND_PARTIAL_EVERY == 0:
                payload = {
                    "Status": "partial",
                    "FilesScanned": all_files_count
                }

                async with aiohttp.ClientSession() as session:
                    await session.post(request.CallbackUrl, json=payload)
        results = await search_secrets(file_path, rules, target_dir)
        all_results.extend(results)

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
