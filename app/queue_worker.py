import asyncio
from app.models import ScanRequest
from app.repo_utils import download_repo, delete_dir, check_ref_and_resolve_azure
from app.scanner import scan_repo
import aiohttp
import os
import tempfile
from typing import Tuple, Optional
import shutil
import random
import string
import subprocess
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
# Load environment variables
load_dotenv()
task_queue = asyncio.Queue()

HubType = os.getenv("HubType")

async def add_to_queue_background(request: ScanRequest, commit: str):
    await task_queue.put((request, commit))
    print(f"📥 Проект {request.ProjectName} поставлен в очередь на сканирование")

async def start_worker():
    while True:
        request, commit = await task_queue.get()
        # Запускаем в отдельной задаче
        asyncio.create_task(process_request_async(request, commit))
        task_queue.task_done()
        
async def process_request(request: ScanRequest, commit: str):
    my_tmp_folder = "tmp"
    os.makedirs(my_tmp_folder, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir="C:\\")
    # print(f"{temp_dir=}")
    try:
        #print(f"{commit=}")
        extracted_repo_path, status_message = await download_repo(request.RepoUrl, commit, temp_dir)
        if extracted_repo_path:
            results, all_files_count = await scan_repo(request, extracted_repo_path, request.ProjectName)

            payload = {
                "Status": "completed",
                "Message": "Scanned Successfully",
                "ProjectName": request.ProjectName,
                "ProjectRepoUrl": request.RepoUrl,
                "RepoCommit": commit,
                "Results": results,
                "FilesScanned": all_files_count
            }

            async with aiohttp.ClientSession() as session:
                await session.post(request.CallbackUrl, json=payload)
            print(f"✅ Результаты сканирования отправлены на CallbackUrl")
        else:
            payload = {
                "Status": "Error",
                "Message": status_message
            }

            async with aiohttp.ClientSession() as session:
                await session.post(request.CallbackUrl, json=payload)
    except Exception as e:
        print(f"Ошибка при обработке: {e}")
        async with aiohttp.ClientSession() as session:
            payload = {
                "Status": "Error",
                "Message": f"{str(e)}",}
            await session.post(request.CallbackUrl, json=payload)
    finally:
        delete_dir(temp_dir)



# # Alternative version that checks existence first, then resolves
# async def ref_exists(repo_url: str, ref_type: str, ref: str) -> bool:
#     """Check if a reference exists in the repository."""
#     exists, _ = await check_ref_and_resolve(repo_url, ref_type, ref)
#     return exists


# async def resolve_ref_to_commit(repo_url: str, ref_type: str, ref: str) -> Optional[str]:
#     """Resolve a reference to its commit hash."""
#     exists, commit_hash = await check_ref_and_resolve(repo_url, ref_type, ref)
#     return commit_hash if exists else None