import os
import zipfile
import tempfile
import requests
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
# from requests_negotiate_sspi import HttpNegotiateAuth
from urllib.parse import urlparse
import io
import shutil
import yaml
from dotenv import load_dotenv
from app.secure_save import decrypt_from_file
import urllib3
import time
import asyncio
import base64
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables
load_dotenv()
# Setup logging to file
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         RotatingFileHandler('secrets_scanner_service.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
#         logging.StreamHandler()  # Также выводить в консоль
#     ]
# )
logger = logging.getLogger("repo_utils")

with open('Settings/excluded_files.yml', 'r') as f:
    data = yaml.safe_load(f)

# Преобразуем список в множество
EXCLUDED_FILES = set(data.get('excluded_files', []))

with open('Settings/excluded_extensions.yml', 'r') as f:
    data = yaml.safe_load(f)

# Преобразуем список в множество
EXCLUDED_EXTENSIONS = set(data.get('excluded_extensions', []))

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
    logger.error(f"Error: {str(error)}")
    logger.error("Если это первый запуск - необходимо запустить мастер настройки Auth данных 'python app/secure_save.py'")

auth_methods = ["basic", "pat"]  # 'pat', 'basic', 'Negotiate' или None


def get_auth(auth_method):
    if auth_method == 'pat' and pat:
        return HTTPBasicAuth("", pat)
    elif auth_method == 'basic' and username and password:
        return HttpNtlmAuth(username, password)
    # elif auth_method == 'Negotiate':
    #     return HttpNegotiateAuth()
    else:
        return None


def parse_azure_devops_url(repo_url):
    parsed = urlparse(repo_url)
    server = parsed.netloc
    path_parts = parsed.path.strip("/").split("/")

    if '_git' not in path_parts:
        raise ValueError("URL не содержит '_git'")

    git_index = path_parts.index('_git')

    if git_index + 1 >= len(path_parts):
        raise ValueError("URL некорректен: отсутствует имя репозитория после '_git'")

    repository = path_parts[git_index + 1]

    # Все части до _git — это путь: /Collection/.../Project
    if git_index < 1:
        raise ValueError("Недостаточно информации до '_git'")

    project = path_parts[git_index - 1]
    collection_parts = path_parts[:git_index - 1]
    collection = "/".join(collection_parts)

    return server, collection, project, repository

async def download_repo(repo_url, commit_id, extract_path, worker_instance=None, ref_type=None):
    """
    Скачивает репозиторий. Определяет тип репозитория по URL.
    
    Args:
        repo_url: URL репозитория
        commit_id: commit hash или ref (для DevZone используется ref напрямую)
        extract_path: путь для извлечения
        worker_instance: экземпляр Worker для отправки heartbeat (опционально)
        ref_type: тип ref для DevZone (branch, tag, commit) - опционально
    
    Returns:
        (extracted_path: str, status: str)
    """
    extracted_path = ""
    
    # Определяем тип репозитория по URL
    if "devzone.local" in repo_url.lower():
        # DevZone репозиторий - используем commit_id как ref_value, ref_type из параметра
        ref_value = commit_id
        # Если ref_type не передан, используем branch по умолчанию
        devzone_ref_type = ref_type if ref_type else "branch"
        
        extracted_path, status = await download_devzone_repo(
            repo_url, devzone_ref_type, ref_value, extract_path, worker_instance
        )
    elif HubType and HubType.lower() == "azure":
        extracted_path, status = await download_repo_azure(repo_url, commit_id, extract_path)
    elif HubType and HubType.lower() == "github":
        extracted_path, status = await download_github_repo(repo_url, commit_id, extract_path)
    else:
        return "", f"Неизвестный тип репозитория или HubType не задан"
    
    return extracted_path, status

def safe_extract(zip_file, extract_path):
    """
    Безопасная распаковка ZIP архива с фильтрацией нежелательных файлов
    
    Args:
        zip_file: ZipFile объект
        extract_path: путь для распаковки
        excluded_extensions: список исключенных расширений (например, ['.exe', '.bat'])
        excluded_files: список исключенных имен файлов (например, ['autorun.inf', 'desktop.ini'])
    """
    
    for member in zip_file.infolist():
        filename = member.filename

        # Игнорируем абсолютные пути и ".."
        if os.path.isabs(filename) or ".." in filename:
            continue
        
        # Получаем только имя файла без пути
        basename = os.path.basename(filename).lower()
        
        # Проверяем исключенные файлы
        if basename in EXCLUDED_FILES:
            continue
        
        # Проверяем исключенные расширения
        file_ext = os.path.splitext(basename)[1]
        if file_ext in EXCLUDED_EXTENSIONS:
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

async def download_repo_azure(repo_url, commit_id, extract_path):
    os.makedirs(extract_path, exist_ok=True)

    try:
        server, collection, project, repo_name = parse_azure_devops_url(repo_url)
    except ValueError as e:
        logger.error(f"Ошибка парсинга URL '{repo_url}': {e}")
        return False

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

    for auth_method in auth_methods:
        download_start = time.time()
        logger.info(f"[DOWNLOAD_AZURE] Скачиваем {repo_name} --> '{commit_id[:7]}'... auth_method: '{auth_method}'")
        
        # Специальная обработка для PAT токена
        if auth_method == 'pat' and pat:
            # Встраиваем PAT токен в URL
            parsed_url = urlparse(api_url)
            pat_api_url = f"{parsed_url.scheme}://:{pat}@{parsed_url.netloc}{parsed_url.path}"
            # И также добавляем в заголовки
            token_b64 = base64.b64encode((':' + pat).encode('ascii')).decode('ascii')
            headers = {
                'Authorization': f'Basic {token_b64}'
            }
            response = requests.get(pat_api_url, params=params, headers=headers, stream=True, verify=False)
        else:
            # Для других методов аутентификации используем обычный подход
            auth = get_auth(auth_method)
            response = requests.get(api_url, params=params, auth=auth, stream=True, verify=False)

        if response.status_code == 200:
            try:
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                    temp_zip_path = temp_file.name
                    temp_file.write(response.content)

                # Логируем размер загруженного архива
                archive_size = os.path.getsize(temp_zip_path)
                logger.info(f"[DOWNLOAD_AZURE] Размер загруженного архива: '{archive_size / 1024 / 1024:.2f} MB'")

                with zipfile.ZipFile(temp_zip_path) as zip_file:
                    zip_file.extractall(extract_path)
                    # safe_extract(zip_file, extract_path)
                
                # Логируем размер распакованного архива
                extracted_size = 0
                for root, dirs, files in os.walk(extract_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            extracted_size += os.path.getsize(file_path)
                        except:
                            pass
                logger.info(f"[DOWNLOAD_AZURE] Размер распакованного архива: '{extracted_size / 1024 / 1024:.2f} MB'")
                
                download_time = time.time() - download_start
                logger.info(f"[DOWNLOAD_AZURE] Репозиторий успешно распакован в: '{extract_path}' (время: {download_time:.2f}с)")
                os.unlink(temp_zip_path)
                return extract_path, "Success"
            
            except Exception as e:
                logger.error(f"[DOWNLOAD_AZURE] Ошибка при распаковке архива: {e}")
                return_string = f"Ошибка при распаковке архива: {e}"
                return "", return_string
            
    logger.error(f"[DOWNLOAD_AZURE] Ошибка при скачивании '{repo_name}': '{response.status_code}'")
    return_string = f"Ошибка при скачивании {repo_name}: {response.status_code}"
    return "", return_string


def extract_github_archive(zip_file, extract_path):
    """
    Извлекает GitHub архив, убирая корневую папку с именем репозитория
    """
    # Получаем список всех файлов в архиве
    file_list = zip_file.namelist()
    
    # Находим корневую папку (первый элемент после разделения по '/')
    if file_list:
        root_folder = file_list[0].split('/')[0] + '/'
        
        # Извлекаем все файлы
        for member in zip_file.infolist():
            # Пропускаем саму корневую папку
            if member.filename == root_folder.rstrip('/'):
                continue
                
            # Убираем корневую папку из пути
            if member.filename.startswith(root_folder):
                # Новый путь без корневой папки
                new_path = member.filename[len(root_folder):]
                
                # Если это не пустой путь
                if new_path:
                    # Создаем полный путь для извлечения
                    target_path = os.path.join(extract_path, new_path)
                    
                    # Создаем директории если нужно
                    if member.is_dir():
                        os.makedirs(target_path, exist_ok=True)
                    else:
                        # Создаем родительские директории
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        
                        # Извлекаем файл
                        with zip_file.open(member) as source:
                            with open(target_path, 'wb') as target:
                                target.write(source.read())

async def download_github_repo(repo_url, commit_id, extract_path):
    """
    Скачивает архив репозитория GitHub на указанном коммите и распаковывает его.
    Исправленная версия без корневой папки в путях.
    """
    os.makedirs(extract_path, exist_ok=True)
    download_start = time.time()
    try:
        repo_url = repo_url.rstrip('/')
        zip_url = f"{repo_url}/archive/{commit_id}.zip"

        logger.info(f"[DOWNLOAD_GIT] Скачиваем {zip_url}...")
        response = requests.get(zip_url, verify=False)
        response.raise_for_status()

        # Логируем размер загруженного архива
        archive_size = len(response.content)
        logger.info(f"[DOWNLOAD_GIT] Размер загруженного архива: '{archive_size / 1024 / 1024:.2f} MB'")

        # ИСПРАВЛЕНИЕ: используем специальную функцию для GitHub архивов
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            extract_github_archive(zip_file, extract_path)

        # Логируем размер распакованной папки
        extracted_size = 0
        for root, dirs, files in os.walk(extract_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    extracted_size += os.path.getsize(file_path)
                except:
                    pass
        logger.info(f"[DOWNLOAD_GIT] Размер распакованного архива: '{extracted_size / 1024 / 1024:.2f} MB'")

        #download_time = time.time() - download_start
        #logger.info(f"Репозиторий успешно скачан и распакован в: {extract_path} (время: {download_time:.2f}с)")
        return extract_path, "Success"
    except requests.HTTPError as http_err:
        logger.error(f"[DOWNLOAD_GIT] HTTP ошибка: {http_err}")
        return_string = f"HTTP ошибка: {http_err}"
        return "", return_string
    except Exception as err:
        logger.error(f"[DOWNLOAD_GIT] Общая ошибка: {err}")
        return_string = f"Общая ошибка: {err}"
        return "", return_string

async def check_ref_and_resolve_azure(repo_url: str, ref_type: str, ref: str):
    """
    Проверка существования ветки, тега или коммита в Azure DevOps и получение commit hash.

    Args:
        repo_url: URL Azure DevOps репозитория
        ref_type: "branch", "tag" или "commit"
        ref: имя ветки/тега или хэш коммита

    Returns:
        (существует: bool, хэш_коммита: Optional[str], сообщение: str)
    """
    message = ""

    for auth_method in auth_methods:
        auth = get_auth(auth_method)
        logger.info(f"Try to resolve {repo_url} --> '{ref_type}'. auth_method='{auth_method}'")

        try:
            server, collection, project, repository = parse_azure_devops_url(repo_url)
            base_api_url = f"https://{server}/{collection}/{project}/_apis/git/repositories/{repository}"

            if ref_type.lower() == "branch":
                url = f"{base_api_url}/refs?filter=heads/{ref}&api-version=5.1-preview.1"
                response = requests.get(url, auth=auth, verify=False, timeout=20)
                if response.status_code not in [200, 201, 202, 203]:
                    if response.status_code in [401, 403]:
                        message = f"Access Denied: [{response.status_code}]. Проверьте, что у PAT-токена/NTLM Auth есть доступ к репозиторию."
                    else:
                        message = f"Запрос к репозиторию выдал {response.status_code} код. Возможно неверные креды или нет доступа к репозиторию"
                    continue
                message = ""
                data = response.json()
                if data.get("count", 0) == 0:
                    return False, None, "Ветка не найдена"
                commit_hash = data["value"][0]["objectId"]
                return True, commit_hash, ""

            elif ref_type.lower() == "tag":
                # Сначала получаем objectId тега
                url = f"{base_api_url}/refs?filter=tags/{ref}&api-version=5.1-preview.1"
                response = requests.get(url, auth=auth, verify=False, timeout=20)
                if response.status_code not in [200, 201, 202, 203]:
                    if response.status_code in [401, 403]:
                        message = f"Access Denied: [{response.status_code}]. Проверьте, что у PAT-токена/NTLM Auth есть доступ к репозиторию."
                    else:
                        message = f"Запрос к репозиторию выдал {response.status_code} код. Возможно неверные креды или нет доступа к репозиторию"
                    continue
                message = ""
                data = response.json()
                if data.get("count", 0) == 0:
                    return False, None, "Тег не найден"

                tag_object_id = data["value"][0]["objectId"]

                # Пробуем получить аннотированный тег
                tag_url = f"{base_api_url}/annotatedtags/{tag_object_id}?api-version=6.1-preview"
                tag_response = requests.get(tag_url, auth=auth, verify=False, timeout=20)

                if tag_response.status_code == 200:
                    tag_data = tag_response.json()
                    tagged_object = tag_data.get("taggedObject", {})
                    if tagged_object.get("objectType") == "commit":
                        return True, tagged_object["objectId"], ""
                    else:
                        return True, tag_object_id, "Не commit-объект, но тег найден"
                else:
                    # fallback если не удалось получить annotated tag
                    return True, tag_object_id, "Не удалось получить аннотированный тег, возвращён objectId"

            elif ref_type.lower() == "commit":
                url = f"{base_api_url}/commits/{ref}?api-version=5.1-preview.1"
                response = requests.get(url, auth=auth, verify=False, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    commit_id = data.get("commitId")
                    if commit_id:
                        return True, commit_id, ""
                    return False, None, "Коммит не найден"
                else:
                    message = ""
                    continue
            else:
                return False, None, f"❌ Неверный тип ref: {ref_type}"

        except Exception as e:
            message = f"Ошибка при проверке Azure DevOps ссылки: {e}"
            logger.error(f"{message}")
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
            # Для GitHub репозиториев используем API
            if "github.com" in repo_url:
                try:
                    # Извлекаем owner и repo из URL
                    parts = repo_url.rstrip('/').split('/')
                    if len(parts) >= 2:
                        owner = parts[-2]
                        repo_name = parts[-1]
                        
                        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/commits/{ref}"
                        
                        import requests
                        response = requests.get(api_url, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            return True, data.get('sha', ref), message
                        elif response.status_code == 404:
                            return False, None, f"Коммит {ref} не найден"
                        else:
                            return False, None, f"GitHub API error: {response.status_code}"
                    else:
                        return False, None, "Неверный формат GitHub URL"
                except Exception as e:
                    return False, None, f"Ошибка GitHub API: {e}"
        else:
            raise ValueError(f"Invalid ref_type: {ref_type}")

        # Для веток и тегов используем git ls-remote
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            stderr_text = stderr.decode() if stderr else "Unknown error"
            return False, None, f"Git ls-remote failed: {stderr_text}"
            
        output = stdout.decode()
        lines = output.splitlines()

        # For tags and branches, find matching reference and extract commit hash
        ref_suffix = f"/{ref}"
        for line in lines:
            if line.endswith(ref_suffix):
                commit_hash = line.split()[0]
                return True, commit_hash, message
        
        # Также проверяем точное совпадение (для случаев без слеша)
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[1].endswith(f"/{ref}"):
                commit_hash = parts[0]
                return True, commit_hash, message
        
        return False, None, f"{ref_type.capitalize()} '{ref}' не найден"

    except Exception as error:
        logger.error(f"Ошибка resolve_git: {error}")
        return False, None, f"Ошибка resolve_git: {error}"


def delete_dir(path: str):
    shutil.rmtree(path, ignore_errors=True)


def parse_devzone_url(repo_url):
    """Парсит URL DevZone репозитория вида https://git.devzone.local/devzone/project/repo"""
    parsed = urlparse(repo_url)
    path_parts = parsed.path.strip("/").split("/")
    
    if len(path_parts) < 3:
        raise ValueError("URL DevZone некорректен: недостаточно частей пути")
    
    # Извлекаем путь для Jenkins Job: devzone/project/repo
    if path_parts[0] != "devzone":
        raise ValueError("URL DevZone должен начинаться с /devzone/")
    
    project_path = "/".join(path_parts)
    project_path = project_path if project_path.endswith(".git") else project_path + ".git"
    
    return project_path


async def check_ref_and_resolve_devzone(repo_url: str, ref_type: str, ref: str):
    """
    Проверка ref для DevZone репозитория.
    Для DevZone валидация ref не требуется (Jenkins Job это сделает).
    
    Args:
        repo_url: URL DevZone репозитория
        ref_type: "branch", "tag" или "commit"
        ref: ref_value (имя ветки/тега или хэш коммита)
    
    Returns:
        (существует: bool, ref_value: str, сообщение: str)
        ref_value возвращается как есть (это значение, которое отправится в Jenkins Job)
    """
    # Валидация ref_type
    valid_ref_types = ["branch", "tag", "commit"]
    if ref_type.lower() not in valid_ref_types:
        return False, None, f"Неверный тип ref: {ref_type}. Допустимые значения: {', '.join(valid_ref_types)}"
    
    # Для DevZone просто возвращаем ref_value как есть (Jenkins Job сам проверит)
    logger.info(f"DevZone ref проверка для {repo_url}: {ref_type}='{ref}' (валидация выполнится в Jenkins Job)")
    return True, ref, ""


async def download_devzone_repo(repo_url, ref_type, ref_value, extract_path, worker_instance=None):
    """
    Асинхронная функция скачивания DevZone репозитория через Jenkins Job.
    
    Args:
        repo_url: URL репозитория DevZone
        ref_type: тип ref (branch, tag, commit)
        ref_value: значение ref (имя ветки/тега или хэш коммита)
        extract_path: путь для извлечения архива
        worker_instance: экземпляр Worker для отправки heartbeat (опционально)
    
    Returns:
        (extract_path: str, status: str)
    
    Note:
        ref_type и ref_value передаются в Jenkins Job как параметры checkout_mode и get_branch соответственно.
        Если TEST_MODE=True в .env, используется локальный архив Tests/test_devzone.zip для тестирования.
    """
    # Проверяем тестовый режим
    test_mode = os.getenv("TEST_MODE", "False").lower() == "true"
    
    if test_mode:
        return await _download_devzone_test_mode(repo_url, ref_type, ref_value, extract_path, worker_instance)
    
    try:
        # Загружаем параметры из переменных окружения
        jenkins_job_url = os.getenv("DEVZONE_JENKINS_JOB_URL")
        jenkins_login = os.getenv("JENKINS_LOGIN")
        jenkins_api_token = os.getenv("JENKINS_API_TOKEN")
        
        if not jenkins_job_url or not jenkins_login or not jenkins_api_token:
            error_msg = "Не заданы переменные окружения для Jenkins (DEVZONE_JENKINS_JOB_URL, JENKINS_LOGIN, JENKINS_API_TOKEN)"
            logger.error(error_msg)
            return "", error_msg
        
        # Парсим URL для получения project_path
        try:
            project_path = parse_devzone_url(repo_url)
        except ValueError as e:
            error_msg = f"Ошибка парсинга URL DevZone: {e}"
            logger.error(error_msg)
            return "", error_msg
        
        # Валидация ref_type
        valid_ref_types = ["branch", "tag", "commit"]
        if ref_type.lower() not in valid_ref_types:
            error_msg = f"Неверный тип ref: {ref_type}. Допустимые значения: {', '.join(valid_ref_types)}"
            logger.error(error_msg)
            return "", error_msg
        
        extract_path = extract_path if extract_path.endswith("/") else f"{extract_path}/"
        os.makedirs(extract_path, exist_ok=True)
        
        logger.info(f"[DOWNLOAD_DEVZONE] Скачиваем {project_path} -> '{ref_type}':'{ref_value}'")
        
        # Создаем сессию для Jenkins API
        session = requests.Session()
        session.auth = (jenkins_login, jenkins_api_token)
        session.verify = False
        
        # Параметры для Jenkins Job
        params = {
            "project_path": project_path,
            "get_branch": ref_value,
            "checkout_mode": ref_type.lower()
        }
        
        # 1. Запуск джобы с параметрами
        logger.info(f"[DOWNLOAD_DEVZONE] Запускаю Jenkins Job: {jenkins_job_url}")
        try:
            r = session.post(f"{jenkins_job_url}buildWithParameters", params=params, timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            error_msg = f"Ошибка запуска Jenkins Job: {e}"
            logger.error(error_msg)
            return "", error_msg
        
        queue_url = r.headers.get("Location")
        if not queue_url:
            error_msg = "Не удалось получить URL очереди Jenkins"
            logger.error(error_msg)
            return "", error_msg
        
        logger.info(f"[DOWNLOAD_DEVZONE] Jenkins Job поставлен в очередь: {queue_url}")
        
        # 2. Ждём, пока билд будет назначен и появится номер
        build_number = None
        queue_wait_start = time.time()
        queue_timeout = 600  # 10 минут на ожидание в очереди
        heartbeat_interval = 15  # Отправлять heartbeat каждые 15 секунд
        last_heartbeat = time.time()
        
        while build_number is None:
            # Проверяем таймаут ожидания в очереди
            if time.time() - queue_wait_start > queue_timeout:
                error_msg = f"Таймаут ожидания в очереди Jenkins ({queue_timeout} сек)"
                logger.error(error_msg)
                return "", error_msg
            
            # Отправляем heartbeat при необходимости
            if worker_instance and (time.time() - last_heartbeat) >= heartbeat_interval:
                worker_instance.send_heartbeat("downloading", force=True, 
                    progress=10, 
                    progress_detail=f"Ожидание Jenkins Job в очереди ({(time.time() - queue_wait_start):.0f} сек)")
                last_heartbeat = time.time()
            
            try:
                r = session.get(f"{queue_url}api/json", timeout=10)
                r.raise_for_status()
                queue_data = r.json()
                
                if "executable" in queue_data and queue_data["executable"] is not None:
                    build_number = queue_data["executable"]["number"]
                    logger.info(f"[DOWNLOAD_DEVZONE] Билд получил номер: {build_number}")
                    break
                
                await asyncio.sleep(2)
                
            except requests.RequestException as e:
                logger.warning(f"[DOWNLOAD_DEVZONE] Ошибка проверки очереди: {e}, повтор через 5 сек")
                await asyncio.sleep(5)
                continue
        
        # 3. Ждём завершения билда
        build_wait_start = time.time()
        build_timeout = 1800  # 30 минут на выполнение билда
        counter = 0
        
        while True:
            # Проверяем таймаут выполнения билда
            if time.time() - build_wait_start > build_timeout:
                error_msg = f"Таймаут выполнения Jenkins Job ({build_timeout} сек)"
                logger.error(error_msg)
                return "", error_msg
            
            # Отправляем heartbeat при необходимости
            if worker_instance and (time.time() - last_heartbeat) >= heartbeat_interval:
                progress = min(50 + int((time.time() - build_wait_start) / build_timeout * 40), 90)
                worker_instance.send_heartbeat("downloading", force=True,
                    progress=progress,
                    progress_detail=f"Jenkins Job #{build_number} выполняется ({(time.time() - build_wait_start):.0f} сек)")
                last_heartbeat = time.time()
            
            try:
                r = session.get(f"{jenkins_job_url}{build_number}/api/json", timeout=10)
                r.raise_for_status()
                data = r.json()
                
                if not data.get("building", False):
                    logger.info(f"[DOWNLOAD_DEVZONE] Билд #{build_number} завершён!")
                    break
                
                if counter % 30 == 0:  # Логируем каждые 30 секунд
                    logger.info(f"[DOWNLOAD_DEVZONE] Build #{build_number} выполняется ({counter} сек)...")
                
                await asyncio.sleep(5)
                counter += 5
                
            except requests.RequestException as e:
                logger.warning(f"[DOWNLOAD_DEVZONE] Ошибка проверки статуса билда: {e}, повтор через 5 сек")
                await asyncio.sleep(5)
                continue
        
        # Проверяем результат билда
        try:
            r = session.get(f"{jenkins_job_url}{build_number}/api/json", timeout=10)
            r.raise_for_status()
            build_data = r.json()
            
            if build_data.get("result") != "SUCCESS":
                error_msg = f"Jenkins Job завершился с ошибкой: {build_data.get('result', 'UNKNOWN')}"
                logger.error(error_msg)
                return "", error_msg
        except requests.RequestException as e:
            logger.warning(f"[DOWNLOAD_DEVZONE] Не удалось проверить результат билда: {e}")
        
        # 4. Скачиваем артефакты
        archive_name = "repository_archive1.zip"
        artifact_url = f"{jenkins_job_url}{build_number}/execution/node/3/ws/{archive_name}"
        
        logger.info(f"[DOWNLOAD_DEVZONE] Скачиваю артефакт: {artifact_url}")
        
        if worker_instance:
            worker_instance.send_heartbeat("downloading", force=True,
                progress=95,
                progress_detail="Скачивание архива из Jenkins")
        
        try:
            resp = session.get(artifact_url, timeout=300, stream=True)
            resp.raise_for_status()
        except requests.RequestException as e:
            error_msg = f"Ошибка скачивания артефакта из Jenkins: {e}"
            logger.error(error_msg)
            return "", error_msg
        
        # Сохраняем архив во временный файл
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
            temp_zip_path = temp_file.name
            for chunk in resp.iter_content(chunk_size=8192):
                temp_file.write(chunk)
        
        # Распаковываем архив
        logger.info(f"[DOWNLOAD_DEVZONE] Распаковываю архив...")
        
        if worker_instance:
            worker_instance.send_heartbeat("downloading", force=True,
                progress=98,
                progress_detail="Распаковка архива")
        
        try:
            with zipfile.ZipFile(temp_zip_path) as zip_file:
                zip_file.extractall(extract_path)
            logger.info(f"[DOWNLOAD_DEVZONE] Архив распакован в: {extract_path}")
        except zipfile.BadZipFile:
            error_msg = "Скачанный файл не является валидным ZIP архивом"
            logger.error(error_msg)
            os.unlink(temp_zip_path)
            return "", error_msg
        except Exception as e:
            error_msg = f"Ошибка распаковки архива: {e}"
            logger.error(error_msg)
            os.unlink(temp_zip_path)
            return "", error_msg
        
        # Удаляем временный ZIP файл
        try:
            os.unlink(temp_zip_path)
        except Exception as e:
            logger.warning(f"[DOWNLOAD_DEVZONE] Не удалось удалить временный файл: {e}")
        
        logger.info(f"[DOWNLOAD_DEVZONE] Репозиторий успешно скачан в: {extract_path}")
        return extract_path, "Success"
        
    except Exception as error:
        error_msg = f"Ошибка скачивания DevZone репозитория: {error}"
        logger.error(error_msg)
        return "", error_msg


async def _download_devzone_test_mode(repo_url, ref_type, ref_value, extract_path, worker_instance=None):
    """
    Тестовый режим скачивания DevZone репозитория.
    Использует локальный архив Tests/test_devzone.zip вместо реального Jenkins Job.
    С вероятностью 10% эмулирует ошибку для тестирования обработки сбоев.
    
    Args:
        repo_url: URL репозитория DevZone
        ref_type: тип ref (branch, tag, commit)
        ref_value: значение ref
        extract_path: путь для извлечения архива
        worker_instance: экземпляр Worker для отправки heartbeat (опционально)
    
    Returns:
        (extract_path: str, status: str)
    """
    import random
    
    # Получаем вероятность ошибки из .env (по умолчанию 10%)
    error_probability = float(os.getenv("TEST_MODE_ERROR_PROBABILITY", "10")) / 100.0
    
    try:
        # Парсим URL для получения project_path
        try:
            project_path = parse_devzone_url(repo_url)
        except ValueError as e:
            error_msg = f"Ошибка парсинга URL DevZone: {e}"
            logger.error(error_msg)
            return "", error_msg
        
        # Валидация ref_type
        valid_ref_types = ["branch", "tag", "commit"]
        if ref_type and ref_type.lower() not in valid_ref_types:
            error_msg = f"Неверный тип ref: {ref_type}. Допустимые значения: {', '.join(valid_ref_types)}"
            logger.error(error_msg)
            return "", error_msg
        
        extract_path = extract_path if extract_path.endswith("/") else f"{extract_path}/"
        os.makedirs(extract_path, exist_ok=True)
        
        # Путь к тестовому архиву
        test_archive_path = os.path.join("Tests", "test_devzone.zip")
        
        if not os.path.exists(test_archive_path):
            error_msg = f"Тестовый архив не найден: {test_archive_path}. Создайте архив для тестового режима."
            logger.error(error_msg)
            return "", error_msg
        
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Начинаю скачивание {project_path} -> '{ref_type}':'{ref_value}'")
        
        # Эмулируем запуск Jenkins Job
        if worker_instance:
            worker_instance.send_heartbeat("downloading", force=True,
                progress=10,
                progress_detail="[TEST_MODE] Запуск Jenkins Job")
        
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Jenkins Job запущен")
        await asyncio.sleep(2)  # Имитация задержки запуска
        
        # Случайная ошибка при запуске джобы (30% от всех ошибок)
        if random.random() < error_probability * 0.3:
            error_type = random.choice([
                "Ошибка запуска Jenkins Job: Connection timeout",
                "Ошибка запуска Jenkins Job: Jenkins server unavailable",
                "Ошибка запуска Jenkins Job: Invalid parameters",
                "Ошибка запуска Jenkins Job: Jenkins queue is full"
            ])
            logger.error(f"[DOWNLOAD_DEVZONE] [TEST_MODE] {error_type}")
            return "", error_type
        
        # Эмулируем ожидание в очереди
        if worker_instance:
            worker_instance.send_heartbeat("downloading", force=True,
                progress=20,
                progress_detail="[TEST_MODE] Ожидание в очереди Jenkins")
        
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Jenkins Job поставлен в очередь")
        await asyncio.sleep(3)
        
        # Случайная ошибка в очереди (20% от всех ошибок)
        if random.random() < error_probability * 0.2:
            error_type = random.choice([
                "Таймаут ожидания в очереди Jenkins (600 сек)",
                "Ошибка в очереди Jenkins: Job cancelled",
                "Ошибка в очереди Jenkins: Build queue timeout"
            ])
            logger.error(f"[DOWNLOAD_DEVZONE] [TEST_MODE] {error_type}")
            return "", error_type
        
        # Эмулируем получение номера билда
        build_number = 123  # Фейковый номер
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Билд получил номер: {build_number}")
        await asyncio.sleep(1)
        
        # Эмулируем выполнение билда
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Build #{build_number} выполняется...")
        
        heartbeat_interval = 15
        last_heartbeat = time.time()
        build_start_time = time.time()
        build_duration = 10  # 10 секунд имитации выполнения
        
        while time.time() - build_start_time < build_duration:
            elapsed = int(time.time() - build_start_time)
            
            # Случайная ошибка во время выполнения билда (40% от всех ошибок)
            if random.random() < error_probability * 0.4:
                error_type = random.choice([
                    f"Jenkins Job завершился с ошибкой: FAILURE",
                    f"Jenkins Job завершился с ошибкой: ABORTED",
                    f"Jenkins Job завершился с ошибкой: UNSTABLE",
                    f"Таймаут выполнения Jenkins Job (1800 сек)"
                ])
                logger.error(f"[DOWNLOAD_DEVZONE] [TEST_MODE] {error_type}")
                return "", error_type
            
            # Отправляем heartbeat при необходимости
            if worker_instance and (time.time() - last_heartbeat) >= heartbeat_interval:
                progress = min(30 + int((elapsed / build_duration) * 50), 90)
                worker_instance.send_heartbeat("downloading", force=True,
                    progress=progress,
                    progress_detail=f"[TEST_MODE] Jenkins Job #{build_number} выполняется ({elapsed} сек)")
                last_heartbeat = time.time()
            
            if elapsed % 5 == 0 and elapsed > 0:
                logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Build #{build_number} выполняется ({elapsed} сек)...")
            
            await asyncio.sleep(1)
        
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Билд #{build_number} завершён!")
        
        # Эмулируем скачивание артефакта
        if worker_instance:
            worker_instance.send_heartbeat("downloading", force=True,
                progress=95,
                progress_detail="[TEST_MODE] Скачивание архива из Jenkins")
        
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Скачиваю артефакт...")
        await asyncio.sleep(2)
        
        # Случайная ошибка при скачивании артефакта (10% от всех ошибок)
        if random.random() < error_probability * 0.1:
            error_type = random.choice([
                "Ошибка скачивания артефакта из Jenkins: Artifact not found",
                "Ошибка скачивания артефакта из Jenkins: Connection timeout",
                "Ошибка скачивания артефакта из Jenkins: File corrupted"
            ])
            logger.error(f"[DOWNLOAD_DEVZONE] [TEST_MODE] {error_type}")
            return "", error_type
        
        # Копируем и распаковываем тестовый архив
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Распаковываю архив...")
        
        if worker_instance:
            worker_instance.send_heartbeat("downloading", force=True,
                progress=98,
                progress_detail="[TEST_MODE] Распаковка архива")
        
        try:
            with zipfile.ZipFile(test_archive_path) as zip_file:
                zip_file.extractall(extract_path)
            logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Архив распакован в: {extract_path}")
        except zipfile.BadZipFile:
            error_msg = "Тестовый архив поврежден или не является валидным ZIP архивом"
            logger.error(error_msg)
            return "", error_msg
        except Exception as e:
            error_msg = f"Ошибка распаковки тестового архива: {e}"
            logger.error(error_msg)
            return "", error_msg
        
        logger.info(f"[DOWNLOAD_DEVZONE] [TEST_MODE] Репозиторий успешно скачан в: {extract_path}")
        return extract_path, "Success"
        
    except Exception as error:
        error_msg = f"Ошибка в тестовом режиме DevZone: {error}"
        logger.error(error_msg)
        return "", error_msg
