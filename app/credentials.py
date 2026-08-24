import os
from typing import Optional

from dotenv import load_dotenv, set_key

from app.secure_save import encrypt_and_save, decrypt_from_file, ENV_PATH

REPO_LOGIN_FILE = "Settings/login.dat"
REPO_PASSWORD_FILE = "Settings/password.dat"
REPO_PAT_FILE = "Settings/pat_token.dat"
JENKINS_LOGIN_FILE = "Settings/jenkins_login.dat"
JENKINS_TOKEN_FILE = "Settings/jenkins_api_token.dat"


def mask_secret(value: Optional[str], visible: int = 4) -> Optional[str]:
    if not value:
        return None
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible)


def _safe_decrypt(file_path: str, key_name: str) -> Optional[str]:
    if not os.path.exists(file_path):
        return None
    try:
        return decrypt_from_file(file_path, key_name=key_name)
    except Exception:
        return None


def get_repo_credentials() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Возвращает (login, password, pat_token) для Azure/GitHub."""
    return (
        _safe_decrypt(REPO_LOGIN_FILE, "LOGIN_KEY"),
        _safe_decrypt(REPO_PASSWORD_FILE, "PASSWORD_KEY"),
        _safe_decrypt(REPO_PAT_FILE, "PAT_KEY"),
    )


def get_jenkins_credentials() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Возвращает (job_url, login, api_token) для DevZone Jenkins."""
    load_dotenv(ENV_PATH, override=True)
    login = _safe_decrypt(JENKINS_LOGIN_FILE, "JENKINS_LOGIN_KEY") or os.getenv("JENKINS_LOGIN")
    api_token = _safe_decrypt(JENKINS_TOKEN_FILE, "JENKINS_API_TOKEN_KEY") or os.getenv("JENKINS_API_TOKEN")
    job_url = os.getenv("DEVZONE_JENKINS_JOB_URL")
    return job_url, login, api_token


def get_credentials_status() -> dict:
    login, password, pat = get_repo_credentials()
    job_url, jenkins_login, jenkins_token = get_jenkins_credentials()

    def _field(value: Optional[str]) -> dict:
        return {
            "configured": bool(value),
            "preview": mask_secret(value),
        }

    return {
        "repo": {
            "login": _field(login),
            "password": _field(password),
            "pat_token": _field(pat),
        },
        "jenkins": {
            "job_url": job_url,
            "login": _field(jenkins_login),
            "api_token": _field(jenkins_token),
        },
    }


def update_repo_credentials(
    login: Optional[str] = None,
    password: Optional[str] = None,
    pat_token: Optional[str] = None,
) -> list[str]:
    updated = []
    if login is not None:
        encrypt_and_save(text=login, filename=REPO_LOGIN_FILE, key_name="LOGIN_KEY")
        updated.append("login")
    if password is not None:
        encrypt_and_save(text=password, filename=REPO_PASSWORD_FILE, key_name="PASSWORD_KEY")
        updated.append("password")
    if pat_token is not None:
        encrypt_and_save(text=pat_token, filename=REPO_PAT_FILE, key_name="PAT_KEY")
        updated.append("pat_token")
    return updated


def update_jenkins_credentials(
    login: Optional[str] = None,
    api_token: Optional[str] = None,
    job_url: Optional[str] = None,
) -> list[str]:
    updated = []
    if login is not None:
        encrypt_and_save(text=login, filename=JENKINS_LOGIN_FILE, key_name="JENKINS_LOGIN_KEY")
        updated.append("login")
    if api_token is not None:
        encrypt_and_save(text=api_token, filename=JENKINS_TOKEN_FILE, key_name="JENKINS_API_TOKEN_KEY")
        updated.append("api_token")
    if job_url is not None:
        set_key(ENV_PATH, "DEVZONE_JENKINS_JOB_URL", job_url)
        load_dotenv(ENV_PATH, override=True)
        updated.append("job_url")
    return updated
