import os
import zipfile
import tempfile
import aiohttp
import aiofiles
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
from requests_negotiate_sspi import HttpNegotiateAuth
from urllib.parse import urlparse
import re
import io
import shutil
import yaml
from dotenv import load_dotenv
from app.secure_save import decrypt_from_file
import urllib3
import asyncio

# Load environment variables
load_dotenv()

with open('Settings/excluded_files.yml', 'r') as f:
    data = yaml.safe_load(f)
EXCLUDED_FILES = set(data.get('excluded_files', []))

with open('Settings/excluded_extensions.yml', 'r') as f:
    data = yaml.safe_load(f)
EXCLUDED_EXTENSIONS = set(data.get('excluded_extensions', []))

# Disable SSL warnings
urllib3.disable_warnings()

HubType = os.getenv("HubType")
MAX_PATH = 250

# Аутентификация
try:
    TOKEN_FILE = "Settings/pat_token.dat"
    LOGIN_FILE = "Settings/login.dat"
    PASSWORD_FILE = "Settings/password.dat"
    pat = decrypt_from_file(TOKEN_FILE, key_name="PAT_KEY")
    username = decrypt_from_file(LOGIN_FILE, key_name="LOGIN_KEY")
    password = decrypt_from_file(PASSWORD_FILE, key_name="PASSWORD_KEY")
except Exception as error:
    print(f"Error: {str(error)}")
    print("Если это первый запуск - необходимо запустить мастер настройки Auth данных `python app/secure_save.py`")

auth_methods = ["pat", "basic", "Negotiate"]

def get_auth(auth_method):
    if auth_method == 'pat' and pat:
        return HTTPBasicAuth("", pat)
    elif auth_method == 'basic' and username and password:
        return HttpNtlmAuth(username, password)
    elif auth_method == 'Negotiate':
        return HttpNegotiateAuth()
    else:
        return None

def parse_azure_devops_url(repo_url):
    parsed = urlparse(repo_url)
    server = parsed.netloc
    path_parts = parsed.path.strip("/").split("/")

    if '_git' not in path_parts:
        raise ValueError("❌ URL не содержит '_git'")

    git_index = path_parts.index('_git')

    if git_index + 1 >= len(path_parts):
        raise ValueError("❌ URL некорректен: отсутствует имя репозитория после '_git'")

    repository = path_parts[git_index + 1]

    if git_index < 1:
        raise ValueError("❌ Недостаточно информации до '_git'")

    project = path_parts[git_index - 1]
    collection_parts = path_parts[:git_index - 1]
    collection = "/".join(collection_parts)

    return server, collection, project, repository

async def download_repo(repo_url, commit_id, extract_path):
    """Асинхронная функция скачивания"""
    if HubType.lower() == "azure":
        return await download_repo_azure_async(repo_url, commit_id, extract_path)
    elif HubType.lower() == "github":
        return await download_github_repo_async(repo_url, commit_id, extract_path)
    return "", "Неизвестный тип репозитория"

def safe_extract(zip_file, extract_path):
    """Безопасная распаковка ZIP архива"""
    for member in zip_file.infolist():
        filename = member.filename

        if os.path.isabs(filename) or ".." in filename:
            continue
        
        basename = os.path.basename(filename).lower()
        
        if basename in EXCLUDED_FILES:
            continue
        
        file_ext = os.path.splitext(basename)[1]
        if file_ext in EXCLUDED_EXTENSIONS:
            continue

        full_path = os.path.join(extract_path, filename)

        if len(full_path) > MAX_PATH:
            base, name = os.path.split(full_path)
            name = name[:100]
            full_path = os.path.join(base, name)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with zip_file.open(member) as source, open(full_path, "wb") as target:
            target.write(source.read())

async def download_repo_azure_async(repo_url, commit_id, extract_path):
    """Асинхронное скачивание Azure DevOps репозитория через requests в executor"""
    os.makedirs(extract_path, exist_ok=True)

    try:
        server, collection, project, repo_name = parse_azure_devops_url(repo_url)
    except ValueError as e:
        print(f"❌ Ошибка парсинга URL '{repo_url}': {e}")
        return "", str(e)

    base_url = f"https://{server}/{collection}"
    api_url = f"{base_url}/{project}/_apis/git/repositories/{repo_name}/items"

    params = {
        "scopePath": "/",
        "versionDescriptor.version": commit_id,
        "versionDescriptor.versionType": "commit",
        "$format": "zip",
        "download": "true",
        "api-version": "5.1-preview.1"
    }

    # Используем requests в executor для поддержки всех типов аутентификации
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _download_azure_sync, api_url, params, repo_name, commit_id, extract_path)

def _download_azure_sync(api_url, params, repo_name, commit_id, extract_path):
    """Синхронное скачивание Azure через requests для executor"""
    import requests
    
    for auth_method in auth_methods:
        print(f"📥 Скачиваю '{repo_name}' --> {commit_id[:7]}... auth_method: {auth_method}")
        auth = get_auth(auth_method)

        try:
            response = requests.get(api_url, params=params, auth=auth, stream=True, verify=False, timeout=300)

            if response.status_code == 200:
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                    temp_zip_path = temp_file.name
                    temp_file.write(response.content)

                with zipfile.ZipFile(temp_zip_path) as zip_file:
                    zip_file.extractall(extract_path)
                
                os.unlink(temp_zip_path)
                print(f"✅ Репозиторий успешно распакован в: {extract_path}")
                return extract_path, "Success"
            else:
                print(f"❌ Auth method {auth_method} failed: {response.status_code}")
                continue
                
        except Exception as e:
            print(f"❌ Error with {auth_method}: {e}")
            continue
    
    return "", f"Все методы аутентификации не сработали для {repo_name}"

async def download_github_repo_async(repo_url, commit_id, extract_path):
    """Асинхронное скачивание GitHub репозитория"""
    os.makedirs(extract_path, exist_ok=True)
    
    try:
        repo_url = repo_url.rstrip('/')
        zip_url = f"{repo_url}/archive/{commit_id}.zip"

        print(f"🔽 Скачиваю {zip_url}... (async)")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=300)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(zip_url) as response:
                if response.status == 200:
                    content = await response.read()
                    
                    # Распаковка в отдельном потоке
                    await asyncio.get_event_loop().run_in_executor(
                        None, _extract_zip_from_bytes, content, extract_path
                    )
                    
                    print(f"✅ Репозиторий успешно скачан и распакован в: {extract_path}")
                    return extract_path, "Success"
                else:
                    error_msg = f"HTTP ошибка: {response.status}"
                    print(f"❌ {error_msg}")
                    return "", error_msg
                    
    except Exception as e:
        error_msg = f"Общая ошибка: {e}"
        print(f"❌ {error_msg}")
        return "", error_msg

def _extract_zip(zip_path, extract_path):
    """Синхронная распаковка для выполнения в executor"""
    with zipfile.ZipFile(zip_path) as zip_file:
        zip_file.extractall(extract_path)

def _extract_zip_from_bytes(content, extract_path):
    """Синхронная распаковка из байтов для выполнения в executor"""
    with zipfile.ZipFile(io.BytesIO(content)) as zip_file:
        zip_file.extractall(extract_path)

# Остальные функции остаются синхронными, так как они быстрые
async def check_ref_and_resolve_azure(repo_url: str, ref_type: str, ref: str):
    """Асинхронная проверка через requests в executor для поддержки NTLM/Negotiate"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_ref_azure_sync, repo_url, ref_type, ref)

def _check_ref_azure_sync(repo_url: str, ref_type: str, ref: str):
    """Синхронная проверка Azure для executor"""
    import requests
    
    message = ""
    for auth_method in auth_methods:
        auth = get_auth(auth_method)
        print(f"Try to resolve {repo_url} --> {ref_type}. auth_method={auth_method}")
        
        try:
            server, collection, project, repository = parse_azure_devops_url(repo_url)
            base_api_url = f"https://{server}/{collection}/{project}/_apis/git/repositories/{repository}"
            api_version = "5.1-preview.1"

            if ref_type.lower() == "branch":
                url = f"{base_api_url}/refs?filter=heads/{ref}&api-version={api_version}"
            elif ref_type.lower() == "tag":
                url = f"{base_api_url}/refs?filter=tags/{ref}&api-version={api_version}"
            elif ref_type.lower() == "commit":
                url = f"{base_api_url}/commits/{ref}?api-version={api_version}"
            else:
                raise ValueError(f"❌ Неверный тип ref: {ref_type}")

            response = requests.get(url, auth=auth, verify=False, timeout=20)
            
            if response.status_code not in [200, 201, 202, 203]:
                if response.status_code in [401, 403]:
                    message = f"Access Denied: [{response.status_code}]. Проверьте, что у PAT-токена/NTLM Auth есть доступ к репозиторию."
                else:
                    message = f"Запрос к репозиторию выдал {response.status_code} код. Возможно неверные креды или нет доступа к репозиторию"
                continue
                
            message = ""
            data = response.json()
            
            if ref_type.lower() in ("branch", "tag"):
                if data.get("count", 0) == 0:
                    return False, None, message
                commit_hash = data["value"][0]["objectId"]
                return True, commit_hash, message
            elif ref_type.lower() == "commit":
                commit_hash = data.get("commitId")
                if commit_hash:
                    return True, commit_hash, message
                return False, None, message
        
        except Exception as e:
            print(f"❌ Ошибка при проверке Azure DevOps ссылки: {e}")
            message = f"Ошибка при проверке Azure DevOps ссылки: {e}"
            return False, None, message
    
    return False, None, message

async def check_ref_and_resolve_git(repo_url: str, ref_type: str, ref: str):
    message = ""
    try:
        if ref_type.lower() == "tag":
            cmd = ["git", "ls-remote", "--tags", repo_url]
        elif ref_type.lower() == "branch":
            cmd = ["git", "ls-remote", "--heads", repo_url]
        elif ref_type.lower() == "commit":
            cmd = ["git", "ls-remote", repo_url]
        else:
            raise ValueError(f"Invalid ref_type: {ref_type}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        stdout, _ = await process.communicate()
        if process.returncode != 0:
            return False, None, message
            
        output = stdout.decode()
        lines = output.splitlines()

        if ref_type.lower() == "commit":
            for line in lines:
                if line.startswith(ref):
                    return True, ref, message
            return False, None, message
        
        else:
            ref_suffix = f"/{ref}"
            for line in lines:
                if line.endswith(ref_suffix):
                    commit_hash = line.split()[0]
                    return True, commit_hash, message
            return False, None, message

    except Exception:
        return False, None, message

def delete_dir(path: str):
    shutil.rmtree(path, ignore_errors=True)