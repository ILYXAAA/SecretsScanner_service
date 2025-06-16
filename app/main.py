from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from app.models import ScanRequest, PATTokenRequest, RulesContent
from app.queue_worker import task_queue, start_worker, add_to_queue_background
from app.model_loader import get_model_instance
from app.repo_utils import check_ref_and_resolve_git, check_ref_and_resolve_azure
import asyncio
import os
import aiofiles
from app.secure_save import encrypt_and_save, decrypt_from_file
from dotenv import load_dotenv
load_dotenv()

HubType = os.getenv("HubType")
app = FastAPI()

# === PAT Token ===

TOKEN_FILE = "Settings/pat_token.dat"
MAX_WORKERS = 10
RULES_PATH = "Settings/rules.yml"
EXCLUDED_EXTENSIONS_PATH = "Settings/excluded_extensions.yml"
EXCLUDED_FILES_PATH = "Settings/excluded_files.yml"

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


# Запускаем worker при старте
@app.on_event("startup")
async def startup_event():
    get_model_instance()
    for _ in range(MAX_WORKERS):
        asyncio.create_task(start_worker())

@app.get("/health")
async def health():
    return {"status": "healthy", "queue_size": task_queue.qsize()}

@app.post("/scan")
async def scan(request: ScanRequest):
    if task_queue.qsize() >= MAX_WORKERS:  # max workers limit
        return JSONResponse(status_code=429, content={
            "status": "maximum workers exceeded",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": "Превышено количество workers, ожидайте"
        })

    try:
        if HubType.lower() == "github":
            exists, commit, message = await check_ref_and_resolve_git(request.RepoUrl, request.RefType, request.Ref)
        else:
            exists, commit, message = await check_ref_and_resolve_azure(request.RepoUrl, request.RefType, request.Ref)
        if not exists:
                if message:
                    return JSONResponse(status_code=400, content={
                        "status": f"validation_failed",
                        "RefType": request.RefType,
                        "Ref": request.Ref,
                        "message": message
                    })
                else:
                    raise ValueError(f"{request.RefType} '{request.Ref}' не найден в репозитории {request.RepoUrl}")
        
        print(f"✅ Commit resolved {commit[0:6]}..")

        response = JSONResponse(
            content={
                "status": "accepted",
                "RefType": request.RefType,
                "Ref": request.Ref,
                "commit": commit,
                "message": "Сканирование добавлено в очередь ✅"
            },
            status_code=200
        )

        asyncio.create_task(add_to_queue_background(request, commit))
        return response
    
    except ValueError as e:
        print("Запрос не принят - validation_failed")
        return JSONResponse(status_code=400, content={
            "status": f"validation_failed",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": str(e)
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
async def rules_info():
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
async def get_rules():
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
async def rules_info():
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
async def get_rules():
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