from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Header, Depends
from fastapi.responses import JSONResponse
from app.models import ScanRequest, PATTokenRequest, RulesContent, MultiScanRequest, MultiScanResponseItem
from app.queue_worker import task_queue, start_worker, add_to_queue_background, add_multi_scan_to_queue, cleanup_executors
from app.model_loader import get_model_instance
from app.repo_utils import check_ref_and_resolve_git, check_ref_and_resolve_azure
import asyncio
import os
import yaml
import aiofiles
from app.secure_save import encrypt_and_save, decrypt_from_file
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from contextlib import asynccontextmanager
import secrets

load_dotenv()
os.system("") # Нужно для отображение цвета в консоли Windows
# Setup logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('secrets_scanner_service.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()  # Также выводить в консоль
    ]
)
logger = logging.getLogger("main")
HubType = os.getenv("HubType")
API_KEY = os.getenv("API_KEY")

async def validate_api_key(x_api_key: str = Header(None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

# === Application Lifecycle ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global worker_tasks
    
    logger.info(f"Запуск сервиса с {MAX_WORKERS} воркерами...")
    
    # Pre-load model in main process
    try:
        get_model_instance()
        logger.info("Модель загружена в основном процессе")
    except Exception as e:
        logger.error(f"Ошибка загрузки модели: {e}")
    
    # Start concurrent workers
    for i in range(MAX_WORKERS):
        task = asyncio.create_task(start_worker())
        worker_tasks.append(task)
        logger.info(f"Воркер {i+1} запущен")
    
    logger.info(f"Сервис готов к обработке запросов")
    
    yield  # Приложение работает
    
    # Shutdown
    logger.warning("Начинаю остановку сервиса...")
    
    try:
        # Cancel all worker tasks with timeout
        logger.info("Отмена worker tasks...")
        for task in worker_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete with timeout
        if worker_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*worker_tasks, return_exceptions=True),
                    timeout=10.0  # Increased timeout
                )
                logger.info("Все worker tasks остановлены")
            except asyncio.TimeoutError:
                logger.error("Timeout при остановке воркеров - принудительная остановка")
        
        # Cleanup executors with timeout
        try:
            await asyncio.wait_for(cleanup_executors(), timeout=15.0)
        except asyncio.TimeoutError:
            logger.error("Timeout при cleanup executors")
        except Exception as e:
            logger.error(f"Ошибка при cleanup: {e}")
        
    except Exception as e:
        logger.error(f"Ошибка при shutdown: {e}")
    finally:
        logger.info("Сервис остановлен")
        
app = FastAPI(lifespan=lifespan)

# Configuration
TOKEN_FILE = "Settings/pat_token.dat"
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))  # Increased default workers
RULES_PATH = "Settings/rules.yml"
EXCLUDED_EXTENSIONS_PATH = "Settings/excluded_extensions.yml"
EXCLUDED_FILES_PATH = "Settings/excluded_files.yml"
FP_FILE_PATH = "Settings/false-positive.yml"

# Global worker tasks list for cleanup
worker_tasks = []

# === PAT Token Endpoints ===

@app.post("/set-pat", dependencies=[Depends(validate_api_key)])
async def set_pat_token(payload: PATTokenRequest):
    if not payload.token:
        raise HTTPException(status_code=400, detail="Token is required")

    try:
        encrypt_and_save(text=payload.token, filename=TOKEN_FILE, key_name="PAT_KEY")
    except Exception as error:
        return {"status": "failed", "message": f"Error: {str(error)}"}
    
    return {"status": "success", "message": "PAT token saved"}

@app.get("/get-pat", dependencies=[Depends(validate_api_key)])
async def get_pat_token():
    try:
        if not os.path.exists(TOKEN_FILE):
            return {"status": "not_found", "message": "Token not set"}

        token = decrypt_from_file(TOKEN_FILE, key_name="PAT_KEY")

        if len(token) < 4:
            masked = "*" * len(token)
        else:
            masked = token[:4] + "*" * (len(token) - 4)
    except Exception as error:
        return {"status": "failed", "message": f"Error: {str(error)}"}
    return {"status": "success", "token": masked}


# === Health Check ===
@app.get("/health", dependencies=[Depends(validate_api_key)])
async def health():
    return {
        "status": "healthy", 
        "queue_size": task_queue.qsize(),
        "max_workers": MAX_WORKERS,
        "active_workers": len(worker_tasks),
        "supports_multi_scan": True
    }

# === Multi-Scanning Endpoint ===
@app.post("/multi_scan", dependencies=[Depends(validate_api_key)])
async def multi_scan(request: MultiScanRequest):
    """Process multiple repositories sequentially"""
    
    # Check queue capacity
    if task_queue.qsize() >= MAX_WORKERS * 2:
        return JSONResponse(status_code=429, content={
            "status": "queue_full",
            "message": f"Очередь переполнена ({task_queue.qsize()} задач). Попробуйте позже.",
            "data": []
        })

    response_data = []
    all_resolved = True
    error_message = ""

    # Validate all repositories first
    for repo in request.repositories:
        try:
            if HubType.lower() == "github":
                exists, commit, message = await check_ref_and_resolve_git(repo.RepoUrl, repo.RefType, repo.Ref)
            else:
                exists, commit, message = await check_ref_and_resolve_azure(repo.RepoUrl, repo.RefType, repo.Ref)
            
            if exists:
                response_data.append(MultiScanResponseItem(
                    ProjectName=repo.ProjectName,
                    RefType=repo.RefType,
                    Ref=repo.Ref,
                    commit=commit
                ))
                logger.info(f"Resolved {repo.ProjectName}: {commit[:6]}")
            else:
                all_resolved = False
                response_data.append(MultiScanResponseItem(
                    ProjectName=repo.ProjectName,
                    RefType=repo.RefType,
                    Ref=repo.Ref,
                    commit="not_found"
                ))
                logger.error(f"Failed to resolve {repo.ProjectName}: {message}")
                if not error_message:
                    error_message = message or f"Не удалось найти {repo.RefType} '{repo.Ref}'"
                    
        except Exception as e:
            all_resolved = False
            response_data.append(MultiScanResponseItem(
                ProjectName=repo.ProjectName,
                RefType=repo.RefType,
                Ref=repo.Ref,
                commit="not_found"
            ))
            logger.error(f"Error resolving {repo.ProjectName}: {e}")
            if not error_message:
                error_message = str(e)

    # Respond based on validation results
    if all_resolved:
        # Convert to format for queue
        multi_scan_items = []
        commits = []
        
        for repo, response_item in zip(request.repositories, response_data):
            multi_scan_items.append({
                "ProjectName": repo.ProjectName,
                "RepoUrl": repo.RepoUrl,
                "RefType": repo.RefType,
                "Ref": repo.Ref,
                "CallbackUrl": repo.CallbackUrl
            })
            commits.append(response_item.commit)
        
        # Add to queue for sequential processing
        await add_multi_scan_to_queue(multi_scan_items, commits)
        
        return JSONResponse(
            content={
                "status": "accepted",
                "message": "Мультисканирование добавлено в очередь",
                "data": [item.dict() for item in response_data],
                "RepoUrl": repo.RepoUrl
            },
            status_code=200
        )
    else:
        return JSONResponse(
            content={
                "status": "validation_failed",
                "message": f"Не удалось отрезолвить коммиты: {error_message}",
                "data": [item.dict() for item in response_data]
            },
            status_code=400
        )

# === Scanning Endpoint ===

@app.post("/scan", dependencies=[Depends(validate_api_key)])
async def scan(request: ScanRequest):
    # Check queue capacity (allow some buffer over max workers)
    if task_queue.qsize() >= MAX_WORKERS * 2:
        return JSONResponse(status_code=429, content={
            "status": "queue_full",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": f"Очередь переполнена ({task_queue.qsize()} задач). Попробуйте позже."
        })

    try:
        # Validate reference exists and resolve to commit
        if HubType.lower() == "github":
            exists, commit, message = await check_ref_and_resolve_git(request.RepoUrl, request.RefType, request.Ref)
        else:
            exists, commit, message = await check_ref_and_resolve_azure(request.RepoUrl, request.RefType, request.Ref)
        
        if not exists:
            if message:
                return JSONResponse(status_code=400, content={
                    "status": "validation_failed",
                    "RefType": request.RefType,
                    "Ref": request.Ref,
                    "message": message
                })
            else:
                raise ValueError(f"{request.RefType} '{request.Ref}' не найден в репозитории {request.RepoUrl}")
        
        logger.info(f"Commit resolved {commit[0:6]}.. для {request.ProjectName}")

        # Add to queue for processing
        await add_to_queue_background(request, commit)
        
        response = JSONResponse(
            content={
                "status": "accepted",
                "RefType": request.RefType,
                "Ref": request.Ref,
                "commit": commit,
                "queue_position": task_queue.qsize(),
                "message": "Сканирование добавлено в очередь"
            },
            status_code=200
        )

        return response
    
    except ValueError as e:
        logger.error(f"Запрос не принят - validation_failed: {e}")
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": str(e)
        })
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}")
        return JSONResponse(status_code=500, content={
            "status": "error",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": "Внутренняя ошибка сервера"
        })

@app.post("/local_scan", dependencies=[Depends(validate_api_key)])
async def local_scan(
    ProjectName: str = Form(...),
    RepoUrl: str = Form(...),
    CallbackUrl: str = Form(...),
    RefType: str = Form(...), 
    Ref: str = Form(...), 
    zip_file: UploadFile = File(...)
):
    """Process uploaded zip file locally"""
    
    try:
        logger.info(f"Получен запрос на локальное сканирование: {ProjectName}")
        # print(f"  - RepoUrl: {RepoUrl}")
        # print(f"  - CallbackUrl: {CallbackUrl}")
        # print(f"  - zip_file.filename: {zip_file.filename}")
        # print(f"  - zip_file.content_type: {zip_file.content_type}")
        
        # Check queue capacity
        if task_queue.qsize() >= MAX_WORKERS * 2:
            return JSONResponse(status_code=429, content={
                "status": "queue_full",
                "message": f"Очередь переполнена ({task_queue.qsize()} задач). Попробуйте позже."
            })

        # Validate file type
        if not zip_file.filename.endswith('.zip'):
            logger.error(f"Неверный тип файла: {zip_file.filename}")
            return JSONResponse(status_code=400, content={
                "status": "validation_failed",
                "message": "Файл должен быть в формате ZIP"
            })

        # Read file content immediately before putting in queue
        logger.info("Читаю содержимое ZIP файла...")
        zip_content = await zip_file.read()
        logger.info(f"Прочитано {len(zip_content)} байт")
        
        # Create request object
        request_dict = {
            "ProjectName": ProjectName,
            "RepoUrl": RepoUrl,
            "RefType": RefType,
            "Ref": Ref,
            "CallbackUrl": CallbackUrl
        }

        # Add to queue with file content instead of file object
        await task_queue.put(("local_scan", request_dict, zip_content))
        logger.info(f"Локальное сканирование {ProjectName} поставлено в очередь")
        
        return JSONResponse(
            content={
                "status": "accepted",
                "ProjectName": ProjectName,
                "queue_position": task_queue.qsize(),
                "message": "Локальное сканирование добавлено в очередь"
            },
            status_code=200
        )
    
    except Exception as e:
        logger.error(f"Ошибка при добавлении локального сканирования: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={
            "status": "error",
            "message": f"Внутренняя ошибка сервера: {str(e)}"
        })



# Валидатор для yml, чтобы не сломать структуру файлов
def validate_yaml_structure(content: str, file_type: str) -> tuple[bool, str]:
    """Валидация YAML структуры для разных типов файлов"""
    
    try:
        data = yaml.safe_load(content)
        if data is None:
            return False, "YAML файл пустой или содержит только комментарии"
        
        # Проверка структуры в зависимости от типа файла
        if file_type == "rules":
            if not isinstance(data, list):
                return False, "Файл rules.yml должен содержать список правил"
            for i, rule in enumerate(data):
                if not isinstance(rule, dict):
                    return False, f"Правило #{i+1} должно быть объектом"
                required_fields = ['id', 'message', 'pattern', 'severity']
                for field in required_fields:
                    if field not in rule:
                        return False, f"Правило #{i+1} должно содержать поле '{field}'"
                    if not isinstance(rule[field], str):
                        return False, f"Поле '{field}' в правиле #{i+1} должно быть строкой"
                        
        elif file_type == "excluded_files":
            if not isinstance(data, dict) or 'excluded_files' not in data:
                return False, "Файл должен содержать ключ 'excluded_files'"
            excluded_files = data['excluded_files']
            if not isinstance(excluded_files, list):
                return False, f"Значение 'excluded_files' должно быть списком, получен {type(excluded_files).__name__}"
                
        elif file_type == "excluded_extensions":
            if not isinstance(data, dict) or 'excluded_extensions' not in data:
                return False, "Файл должен содержать ключ 'excluded_extensions'"
            excluded_extensions = data['excluded_extensions']
            if not isinstance(excluded_extensions, list):
                return False, f"Значение 'excluded_extensions' должно быть списком, получен {type(excluded_extensions).__name__}"
                
        elif file_type == "false_positive":
            if not isinstance(data, dict) or 'false_positive' not in data:
                return False, "Файл должен содержать ключ 'false_positive'"
            false_positive = data['false_positive']
            if not isinstance(false_positive, list):
                return False, f"Значение 'false_positive' должно быть списком, получен {type(false_positive).__name__}"
                
        return True, "Структура YAML корректна"
        
    except yaml.YAMLError as e:
        # Упрощаем сообщение об ошибке YAML
        error_msg = str(e)
        if "expected <block end>" in error_msg:
            return False, "Ошибка структуры YAML: неправильное форматирование списка или объекта"
        elif "found unexpected" in error_msg:
            return False, "Ошибка синтаксиса YAML: неожиданный символ"
        else:
            return False, f"Ошибка синтаксиса YAML: {error_msg}"
    except Exception as e:
        return False, f"Ошибка валидации: {str(e)}"

###########################
# Rules.yml ###############
###########################
@app.get("/rules-info", dependencies=[Depends(validate_api_key)])
async def rules_info():
    if os.path.exists(RULES_PATH):
        stat = os.stat(RULES_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(RULES_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(RULES_PATH)
    }

@app.get("/get-rules", dependencies=[Depends(validate_api_key)])
async def get_rules():
    try:
        if not os.path.exists(RULES_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(RULES_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "rules": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-rules", dependencies=[Depends(validate_api_key)])
async def update_rules(data: RulesContent):
    try:
        info = await update_rules_file(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed", 
            "message": str(e),
            "filename": RULES_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": RULES_PATH,
            "size": 0
        })
    
async def update_rules_file(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "rules")
    if not is_valid:
        raise ValueError(f"Некорректная структура rules.yml: {error_msg}")
    
    # Заменяем \r\n и \r на \n (унифицированный формат)
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(RULES_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(RULES_PATH)
    return {
        "message": f"Файл {RULES_PATH} успешно обновлен",
        "filename": RULES_PATH,
        "size": size
    }

###########################
# excluded_files.yml ######
###########################
@app.get("/excluded-files-info", dependencies=[Depends(validate_api_key)])
async def excluded_files_info():
    if os.path.exists(EXCLUDED_FILES_PATH):
        stat = os.stat(EXCLUDED_FILES_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(EXCLUDED_FILES_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(EXCLUDED_FILES_PATH)
    }

@app.get("/get-excluded-files", dependencies=[Depends(validate_api_key)])
async def get_excluded_files():
    try:
        if not os.path.exists(EXCLUDED_FILES_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(EXCLUDED_FILES_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "excluded_files": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-excluded-files", dependencies=[Depends(validate_api_key)])
async def update_excluded_files(data: RulesContent):
    try:
        info = await do_update_excluded_files(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        # Специально обрабатываем ошибки валидации
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "message": str(e),
            "filename": EXCLUDED_FILES_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": EXCLUDED_FILES_PATH,
            "size": 0
        })
    
async def do_update_excluded_files(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "excluded_files")
    if not is_valid:
        raise ValueError(f"Некорректная структура excluded_files.yml: {error_msg}")
    
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(EXCLUDED_FILES_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(EXCLUDED_FILES_PATH)
    return {
        "message": f"Файл {EXCLUDED_FILES_PATH} успешно обновлен",
        "filename": EXCLUDED_FILES_PATH,
        "size": size
    }

###########################
# excluded_extensions.yml #
###########################
@app.get("/excluded-extensions-info", dependencies=[Depends(validate_api_key)])
async def excluded_extensions_info():
    if os.path.exists(EXCLUDED_EXTENSIONS_PATH):
        stat = os.stat(EXCLUDED_EXTENSIONS_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(EXCLUDED_EXTENSIONS_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(EXCLUDED_EXTENSIONS_PATH)
    }

@app.get("/get-excluded-extensions", dependencies=[Depends(validate_api_key)])
async def get_excluded_extensions():
    try:
        if not os.path.exists(EXCLUDED_EXTENSIONS_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(EXCLUDED_EXTENSIONS_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "excluded_extensions": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-excluded-extensions", dependencies=[Depends(validate_api_key)])
async def update_excluded_extensions(data: RulesContent):
    try:
        info = await do_update_excluded_extensions(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "message": str(e), 
            "filename": EXCLUDED_EXTENSIONS_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": EXCLUDED_EXTENSIONS_PATH,
            "size": 0
        })
    
async def do_update_excluded_extensions(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "excluded_extensions")
    if not is_valid:
        raise ValueError(f"Некорректная структура excluded_extensions.yml: {error_msg}")
    
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(EXCLUDED_EXTENSIONS_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(EXCLUDED_EXTENSIONS_PATH)
    return {
        "message": f"Файл {EXCLUDED_EXTENSIONS_PATH} успешно обновлен",
        "filename": EXCLUDED_EXTENSIONS_PATH,
        "size": size
    }


##########################################
# False-Positive Rules.yml ###############
##########################################
@app.get("/rules-fp-info", dependencies=[Depends(validate_api_key)])
async def rules_fp_info():
    if os.path.exists(FP_FILE_PATH):
        stat = os.stat(FP_FILE_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(FP_FILE_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(FP_FILE_PATH)
    }

@app.get("/get-fp-rules", dependencies=[Depends(validate_api_key)])
async def get_fp_rules():
    try:
        if not os.path.exists(FP_FILE_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(FP_FILE_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "fp_rules": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-fp-rules", dependencies=[Depends(validate_api_key)])
async def update_fp_rules(data: RulesContent):
    try:
        info = await update_fp_rules_file(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "message": str(e),
            "filename": FP_FILE_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": FP_FILE_PATH,
            "size": 0
        })
    
async def update_fp_rules_file(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "false_positive")
    if not is_valid:
        raise ValueError(f"Некорректная структура false-positive.yml: {error_msg}")
    
    # Заменяем \r\n и \r на \n
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(FP_FILE_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(FP_FILE_PATH)
    return {
        "message": f"Файл {FP_FILE_PATH} успешно обновлен",
        "filename": FP_FILE_PATH,
        "size": size
    }