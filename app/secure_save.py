import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv, set_key

ENV_PATH = ".env"
load_dotenv(ENV_PATH)

def generate_key(KEY_NAME):
    key = Fernet.generate_key().decode()
    set_key(ENV_PATH, KEY_NAME, key)
    load_dotenv(ENV_PATH, override=True)
    return key

def get_key(KEY_NAME):
    key = os.getenv(KEY_NAME)
    if key is None:
        raise ValueError("Ключ не найден в .env")
    return key

def get_or_create_key(KEY_NAME):
    key = os.getenv(KEY_NAME)
    if key is None:
        key = generate_key(KEY_NAME)
    return key

def encrypt_and_save(text: str, filename: str, key_name):
    key = get_or_create_key(key_name)
    fernet = Fernet(key.encode())
    encrypted = fernet.encrypt(text.encode())

    with open(filename, "wb") as file:
        file.write(encrypted)

def decrypt_from_file(filename: str, key_name: str) -> str:
    key = get_key(key_name)
    fernet = Fernet(key.encode())

    if not os.path.exists(filename):
        raise FileNotFoundError(f"Файл {filename} не найден")

    with open(filename, "rb") as file:
        encrypted = file.read()

    decrypted = fernet.decrypt(encrypted)
    return decrypted.decode()

def configure_first_setup():
    print("Мастер первичной настройки login, password, pat")
    print("Убедитесь что запускаетесь из main директории (python app/secure_save.py)")
    print("="*20)
    filename = "Settings/login.dat"
    key_name = "LOGIN_KEY"
    message = input("Введите логин (NTLM Auth):")
    encrypt_and_save(text=message, filename=filename, key_name=key_name)

    filename = "Settings/password.dat"
    key_name = "PASSWORD_KEY"
    message = input("Введите пароль (NTLM Auth):")
    encrypt_and_save(text=message, filename=filename, key_name=key_name)

    filename = "Settings/pat_token.dat"
    key_name = "PAT_KEY"
    message = input("Введите PAT токен:")
    encrypt_and_save(text=message, filename=filename, key_name=key_name)

if __name__ == "__main__":
    print("Мастер первичной настройки login, password, pat")
    print("Убедитесь что запускаетесь из main директории (python app/secure_save.py)")
    print("="*20)
    filename = "Settings/login.dat"
    key_name = "LOGIN_KEY"
    message = input("Введите логин (NTLM Auth):")
    encrypt_and_save(text=message, filename=filename, key_name=key_name)

    filename = "Settings/password.dat"
    key_name = "PASSWORD_KEY"
    message = input("Введите пароль (NTLM Auth):")
    encrypt_and_save(text=message, filename=filename, key_name=key_name)

    filename = "Settings/pat_token.dat"
    key_name = "PAT_KEY"
    message = input("Введите PAT токен:")
    encrypt_and_save(text=message, filename=filename, key_name=key_name)