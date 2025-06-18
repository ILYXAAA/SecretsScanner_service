from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from app.models import ScanRequest, PATTokenRequest, RulesContent, MultiScanRequest, MultiScanResponse, MultiScanResponseItem
from app.queue_worker import task_queue, start_worker, add_to_queue_background, add_multi_scan_to_queue, cleanup_executors
from app.model_loader import get_model_instance
from app.repo_utils import check_ref_and_resolve_git, check_ref_and_resolve_azure
import asyncio
import os
import aiofiles
from app.secure_save import encrypt_and_save, decrypt_from_file
from dotenv import load_dotenv
import signal
import sys

load_dotenv()

HubType = os.getenv("HubType")
app = FastAPI()

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

@app.post("/set-pat")
async def set_pat_token(payload: PATTokenRequest):
    if not payload.token:
        raise HTTPException(status_code=400, detail="Token is required")

    try:
        encrypt_and_save(text=payload.token, filename=TOKEN_FILE, key_name="PAT_KEY")
    except Exception as error:
        return {"status": "failed", "message": f"Error: {str(error)}"}
    
    return {"status": "success", "message": "PAT token saved"}

@app.get("/get-pat")
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

# === Application Lifecycle ===

@app.on_event("startup")
async def startup_event():
    """Initialize model and start concurrent workers"""
    global worker_tasks
    
    print(f"🚀 Запуск сервиса с {MAX_WORKERS} воркерами...")
    
    # Pre-load model in main process
    try:
        get_model_instance()
        print("✅ Модель загружена в основном процессе")
    except Exception as e:
        print(f"⚠️ Ошибка загрузки модели: {e}")
    
    # Start concurrent workers
    for i in range(MAX_WORKERS):
        task = asyncio.create_task(start_worker())
        worker_tasks.append(task)
        print(f"✅ Воркер {i+1} запущен")
    
    print(f"🎯 Сервис готов к обработке запросов")

@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown"""
    global worker_tasks
    
    print("🛑 Начинаю остановку сервиса...")
    
    try:
        # Cancel all worker tasks
        for task in worker_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete with timeout
        if worker_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*worker_tasks, return_exceptions=True),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                print("⚠️ Timeout при остановке воркеров")
        
        # Cleanup executors
        try:
            await cleanup_executors()
        except Exception as e:
            print(f"⚠️ Ошибка при очистке executors: {e}")
        
    except Exception as e:
        print(f"⚠️ Ошибка при shutdown: {e}")
    finally:
        print("✅ Сервис остановлен")

# === Health Check ===

@app.get("/health")
async def health():
    return {
        "status": "healthy", 
        "queue_size": task_queue.qsize(),
        "max_workers": MAX_WORKERS,
        "active_workers": len(worker_tasks),
        "supports_multi_scan": True
    }

# === Multi-Scanning Endpoint ===

@app.post("/multi_scan")
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
                print(f"✅ Resolved {repo.ProjectName}: {commit[:6]}")
            else:
                all_resolved = False
                response_data.append(MultiScanResponseItem(
                    ProjectName=repo.ProjectName,
                    RefType=repo.RefType,
                    Ref=repo.Ref,
                    commit="not_found"
                ))
                print(f"❌ Failed to resolve {repo.ProjectName}: {message}")
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
            print(f"❌ Error resolving {repo.ProjectName}: {e}")
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
                "message": "Мультисканирование добавлено в очередь ✅",
                "data": [item.dict() for item in response_data]
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

@app.post("/scan")
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
        
        print(f"✅ Commit resolved {commit[0:6]}.. для {request.ProjectName}")

        # Add to queue for processing
        await add_to_queue_background(request, commit)
        
        response = JSONResponse(
            content={
                "status": "accepted",
                "RefType": request.RefType,
                "Ref": request.Ref,
                "commit": commit,
                "queue_position": task_queue.qsize(),
                "message": "Сканирование добавлено в очередь ✅"
            },
            status_code=200
        )

        return response
    
    except ValueError as e:
        print(f"❌ Запрос не принят - validation_failed: {e}")
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": str(e)
        })
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        return JSONResponse(status_code=500, content={
            "status": "error",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": "Внутренняя ошибка сервера"
        })

###########################
# Rules.yml ###############
###########################
@app.get("/rules-info")
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

@app.get("/get-rules")
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

@app.post("/update-rules")
async def update_rules(data: RulesContent):
    try:
        info = await update_rules_file(data.content)
        return {"status": "success", **info}
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": RULES_PATH,
            "size": 0
        }
    
async def update_rules_file(content: str):
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
@app.get("/excluded-files-info")
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

@app.get("/get-excluded-files")
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

@app.post("/update-excluded-files")
async def update_excluded_files(data: RulesContent):
    try:
        info = await do_update_excluded_files(data.content)
        return {"status": "success", **info}
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": EXCLUDED_FILES_PATH,
            "size": 0
        }
    
async def do_update_excluded_files(content: str):
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
@app.get("/excluded-extensions-info")
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

@app.get("/get-excluded-extensions")
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

@app.post("/update-excluded-extensions")
async def update_excluded_extensions(data: RulesContent):
    try:
        info = await do_update_excluded_extensions(data.content)
        return {"status": "success", **info}
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": EXCLUDED_EXTENSIONS_PATH,
            "size": 0
        }
    
async def do_update_excluded_extensions(content: str):
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(EXCLUDED_EXTENSIONS_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(EXCLUDED_EXTENSIONS_PATH)
    return {
        "message": f"Файл {EXCLUDED_EXTENSIONS_PATH} успешно обновлен",
        "filename": EXCLUDED_EXTENSIONS_PATH,
        "size": size
    }

# Remove custom signal handlers - let uvicorn handle them



##########################################
# False-Positive Rules.yml ###############
##########################################
@app.get("/rules-fp-info")
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

@app.get("/get-fp-rules")
async def get_fp_rules():
    try:
        if not os.path.exists(FP_FILE_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(FP_FILE_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "rules": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-fp-rules")
async def update_fp_rules(data: RulesContent):
    try:
        info = await update_fp_rules_file(data.content)
        return {"status": "success", **info}
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": FP_FILE_PATH,
            "size": 0
        }
    
async def update_fp_rules_file(content: str):
    # Заменяем \r\n и \r на \n (унифицированный формат)
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(FP_FILE_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(FP_FILE_PATH)
    return {
        "message": f"Файл {FP_FILE_PATH} успешно обновлен",
        "filename": FP_FILE_PATH,
        "size": size
    }