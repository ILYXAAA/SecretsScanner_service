import os
import zipfile
import tempfile
import requests
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
from requests_negotiate_sspi import HttpNegotiateAuth
from urllib.parse import urlparse
import aiohttp
import re
import io
import shutil
from dotenv import load_dotenv
from app.secure_save import decrypt_from_file
import urllib3
import asyncio
# Load environment variables
load_dotenv()

# Disable SSL warnings
urllib3.disable_warnings()

# Load environment variables
load_dotenv()

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

auth_methods = ["pat", "basic", "Negotiate"]  # 'pat', 'basic', 'Negotiate' или None


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

    # Все части до _git — это путь: /Collection/.../Project
    if git_index < 1:
        raise ValueError("❌ Недостаточно информации до '_git'")

    project = path_parts[git_index - 1]
    collection_parts = path_parts[:git_index - 1]
    collection = "/".join(collection_parts)

    return server, collection, project, repository

async def download_repo(repo_url, commit_id, extract_path):
    extracted_path = ""
    if HubType.lower() == "azure":
        extracted_path, status = download_repo_azure(repo_url, commit_id, extract_path)
    elif HubType.lower() == "github":
        extracted_path, status = download_github_repo(repo_url, commit_id, extract_path)
    return extracted_path, status

def safe_extract(zip_file, extract_path):
    for member in zip_file.infolist():
        filename = member.filename

        # Игнорируем абсолютные пути и ".."
        if os.path.isabs(filename) or ".." in filename:
            continue

        full_path = os.path.join(extract_path, filename)

        # Если слишком длинный — обрезаем путь
        if len(full_path) > MAX_PATH:
            base, name = os.path.split(full_path)
            name = name[:100]  # Обрезаем имя файла
            full_path = os.path.join(base, name)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with zip_file.open(member) as source, open(full_path, "wb") as target:
            target.write(source.read())

def download_repo_azure(repo_url, commit_id, extract_path):
    os.makedirs(extract_path, exist_ok=True)

    try:
        server, collection, project, repo_name = parse_azure_devops_url(repo_url)
    except ValueError as e:
        print(f"❌ Ошибка парсинга URL '{repo_url}': {e}")
        return False

    base_url = f"http://{server}/{collection}"
    api_url = f"{base_url}/{project}/_apis/git/repositories/{repo_name}/items"

    params = {
        "scopePath": "/",
        "versionDescriptor.version": commit_id,
        "versionDescriptor.versionType": "commit",
        "$format": "zip",
        "download": "true",
        "api-version": "5.1-preview.1"
    }

    for auth_method in auth_methods:
        print(f"📥 Скачиваем '{repo_name}' --> {commit_id[:7]}... auth_method: {auth_method}")
        auth = get_auth(auth_method)

        response = requests.get(api_url, params=params, auth=auth, stream=True)

        if response.status_code == 200:
            try:
                zip_content = io.BytesIO(response.content)
                with zipfile.ZipFile(zip_content) as zip_file:
                    safe_extract(zip_file, extract_path)
                print(f"✅ Репозиторий успешно распакован в: {extract_path}")
                return extract_path, "Success"
            except Exception as e:
                print(f"❌ Ошибка при распаковке архива: {e}")
                return_string = f"Ошибка при распаковке архива: {e}"
                return "", return_string
            
    print(f"❌ Ошибка при скачивании {repo_name}: {response.status_code}")
    return_string = f"Ошибка при скачивании {repo_name}: {response.status_code}"
    return "", return_string

def download_github_repo(repo_url, commit_id, extract_path):
    """
    Скачивает архив репозитория GitHub на указанном коммите и распаковывает его.

    :param repo_url: URL на репозиторий GitHub, например https://github.com/user/repo
    :param commit_id: Хеш коммита
    :param extract_path: Путь для распаковки архива
    """
    os.makedirs(extract_path, exist_ok=True)
    try:
        # Убедимся, что URL не заканчивается на /
        repo_url = repo_url.rstrip('/')

        # Формируем ссылку на zip архив коммита
        zip_url = f"{repo_url}/archive/{commit_id}.zip"

        print(f"🔽 Скачиваем {zip_url}...")

        # Скачиваем zip архив
        response = requests.get(zip_url)
        response.raise_for_status()

        # Распаковываем архив в указанную папку
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            zip_file.extractall(extract_path)

        print(f"✅ Репозиторий успешно скачан и распакован в: {extract_path}")
        return extract_path, "Success"
    except requests.HTTPError as http_err:
        print(f"❌ HTTP ошибка: {http_err}")
        return_string = f"HTTP ошибка: {http_err}"
        return "", return_string
    except Exception as err:
        print(f"❌ Общая ошибка: {err}")
        return_string = f"Общая ошибка: {err}"
        return "", return_string

async def check_ref_and_resolve_azure(repo_url: str, ref_type: str, ref: str):
    message = ""
    for auth_method in auth_methods:
        auth = get_auth(auth_method)
        print(f"Try to resolve {repo_url} --> {ref_type}. auth_method={auth_method}")
        """
        Проверка существования ветки, тега или коммита в Azure DevOps и получение commit hash.
        
        Args:
            repo_url: URL Azure DevOps репозитория
            ref_type: "branch", "tag" или "commit"
            ref: имя ветки/тега или хэш коммита
            auth: объект авторизации, возвращаемый get_auth()
            
        Returns:
            (существует: bool, хэш_коммита: Optional[str])
        """
        try:
            server, collection, project, repository = parse_azure_devops_url(repo_url)

            base_api_url = f"http://{server}/{collection}/{project}/_apis/git/repositories/{repository}"
            api_version = "5.1-preview.1"

            if ref_type.lower() == "branch":
                url = f"{base_api_url}/refs?filter=heads/{ref}&api-version={api_version}"
            elif ref_type.lower() == "tag":
                url = f"{base_api_url}/refs?filter=tags/{ref}&api-version={api_version}"
            elif ref_type.lower() == "commit":
                url = f"{base_api_url}/commits/{ref}?api-version={api_version}"
            else:
                raise ValueError(f"❌ Неверный тип ref: {ref_type}")

            response = requests.get(url, auth=auth)
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
    """
    Check if a tag, branch, or commit exists in a repo and return its commit hash.
    
    Args:
        repo_url: Git repository URL
        ref_type: "tag", "branch", or "commit"
        ref: Reference name or commit hash
        
    Returns:
        Tuple of (exists: bool, commit_hash: Optional[str])
    """
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
            # For commits, check if any line starts with the commit hash
            for line in lines:
                if line.startswith(ref):
                    return True, ref, message
            return False, None, message
        
        else:
            # For tags and branches, find matching reference and extract commit hash
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

