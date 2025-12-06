import os
import re
import json
import zipfile
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger("model_version_manager")

# Пути к директориям
DATASETS_DIR = "Datasets"
MODELS_DIR = "Model"
CURRENT_VERSION_FILE = os.path.join(MODELS_DIR, "current_version.txt")


def parse_version(version_str: str) -> tuple:
    """
    Парсит версию вида 'v1.0' в кортеж (1, 0) для сравнения
    """
    match = re.match(r'v(\d+)\.(\d+)', version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)))
    return (0, 0)


def compare_versions(v1: str, v2: str) -> int:
    """
    Сравнивает две версии. Возвращает -1 если v1 < v2, 0 если равны, 1 если v1 > v2
    """
    v1_tuple = parse_version(v1)
    v2_tuple = parse_version(v2)
    if v1_tuple < v2_tuple:
        return -1
    elif v1_tuple > v2_tuple:
        return 1
    return 0


def get_all_dataset_versions() -> List[str]:
    """
    Сканирует папку Datasets и возвращает список всех версий датасетов
    """
    versions = []
    if not os.path.exists(DATASETS_DIR):
        logger.warning(f"Директория {DATASETS_DIR} не найдена")
        return versions
    
    for item in os.listdir(DATASETS_DIR):
        item_path = os.path.join(DATASETS_DIR, item)
        if os.path.isdir(item_path) and re.match(r'^v\d+\.\d+$', item):
            versions.append(item)
    
    # Сортируем версии по номеру
    versions.sort(key=lambda v: parse_version(v))
    return versions


def get_all_model_versions() -> List[str]:
    """
    Сканирует папку Model и возвращает список всех версий моделей
    """
    versions = []
    if not os.path.exists(MODELS_DIR):
        logger.warning(f"Директория {MODELS_DIR} не найдена")
        return versions
    
    for item in os.listdir(MODELS_DIR):
        item_path = os.path.join(MODELS_DIR, item)
        if os.path.isdir(item_path) and re.match(r'^v\d+\.\d+$', item):
            versions.append(item)
    
    # Сортируем версии по номеру
    versions.sort(key=lambda v: parse_version(v))
    return versions


def get_current_model_version() -> Optional[str]:
    """
    Читает текущую версию модели из current_version.txt
    Если файл не существует, возвращает последнюю доступную версию модели
    """
    # Пытаемся прочитать из файла
    if os.path.exists(CURRENT_VERSION_FILE):
        try:
            with open(CURRENT_VERSION_FILE, 'r', encoding='utf-8') as f:
                version = f.read().strip()
                if version and re.match(r'^v\d+\.\d+$', version):
                    # Проверяем, что модель для этой версии существует
                    model_path = os.path.join(MODELS_DIR, version, "secret_detector_model.pkl")
                    if os.path.exists(model_path):
                        return version
                    else:
                        logger.warning(f"Модель для версии {version} не найдена, ищу последнюю доступную")
        except Exception as e:
            logger.error(f"Ошибка при чтении {CURRENT_VERSION_FILE}: {e}")
    
    # Если файла нет или версия невалидна, ищем последнюю доступную версию
    model_versions = get_all_model_versions()
    if model_versions:
        latest_version = model_versions[-1]
        logger.info(f"Используется последняя доступная версия модели: {latest_version}")
        return latest_version
    
    # Если нет моделей, ищем последнюю версию датасетов
    dataset_versions = get_all_dataset_versions()
    if dataset_versions:
        latest_version = dataset_versions[-1]
        logger.info(f"Моделей не найдено, будет использована версия датасетов: {latest_version}")
        return latest_version
    
    return None


def set_current_model_version(version: str) -> bool:
    """
    Записывает версию модели в current_version.txt
    """
    try:
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(CURRENT_VERSION_FILE, 'w', encoding='utf-8') as f:
            f.write(version)
        logger.info(f"Текущая версия модели установлена: {version}")
        return True
    except Exception as e:
        logger.error(f"Ошибка при записи {CURRENT_VERSION_FILE}: {e}")
        return False


def ensure_datasets_extracted(version: str) -> bool:
    """
    Проверяет наличие .txt файлов датасетов для указанной версии.
    Если файлов нет, но есть Datasets.zip - распаковывает его.
    Возвращает True если датасеты доступны, False в противном случае.
    """
    version_dir = os.path.join(DATASETS_DIR, version)
    if not os.path.exists(version_dir):
        logger.error(f"Директория версии {version} не найдена: {version_dir}")
        return False
    
    secrets_file = os.path.join(version_dir, "Dataset_Secrets.txt")
    non_secrets_file = os.path.join(version_dir, "Dataset_NonSecrets.txt")
    zip_file = os.path.join(version_dir, "Datasets.zip")
    
    # Проверяем наличие .txt файлов
    if os.path.exists(secrets_file) and os.path.exists(non_secrets_file):
        logger.debug(f"Датасеты для версии {version} уже распакованы")
        return True
    
    # Если файлов нет, проверяем наличие zip
    if not os.path.exists(zip_file):
        logger.error(f"Не найдены датасеты для версии {version}: нет ни .txt файлов, ни Datasets.zip")
        return False
    
    # Распаковываем zip
    try:
        logger.info(f"Распаковываю Datasets.zip для версии {version}")
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(version_dir)
        
        # Проверяем, что файлы появились
        if os.path.exists(secrets_file) and os.path.exists(non_secrets_file):
            logger.info(f"Датасеты для версии {version} успешно распакованы")
            return True
        else:
            logger.error(f"После распаковки Datasets.zip для версии {version} не найдены необходимые файлы")
            return False
    except Exception as e:
        logger.error(f"Ошибка при распаковке Datasets.zip для версии {version}: {e}")
        return False


def get_dataset_description(version: str) -> str:
    """
    Читает описание датасета из description.txt
    Если файл не существует, возвращает "Без описания"
    """
    description_file = os.path.join(DATASETS_DIR, version, "description.txt")
    if os.path.exists(description_file):
        try:
            with open(description_file, 'r', encoding='utf-8') as f:
                description = f.read().strip()
                return description if description else "Без описания"
        except Exception as e:
            logger.error(f"Ошибка при чтении description.txt для версии {version}: {e}")
            return "Без описания"
    return "Без описания"


def save_model_info(version: str, secrets_size: int, non_secrets_size: int, description: str) -> bool:
    """
    Создает файл model_info.json в папке версии модели
    """
    model_version_dir = os.path.join(MODELS_DIR, version)
    os.makedirs(model_version_dir, exist_ok=True)
    
    model_info = {
        "version": version,
        "date": datetime.now().isoformat(),
        "description": description,
        "SecretsSize": secrets_size,
        "NonSecretsSize": non_secrets_size
    }
    
    model_info_path = os.path.join(model_version_dir, "model_info.json")
    try:
        with open(model_info_path, 'w', encoding='utf-8') as f:
            json.dump(model_info, f, ensure_ascii=False, indent=4)
        logger.info(f"Информация о модели сохранена: {model_info_path}")
        return True
    except Exception as e:
        logger.error(f"Ошибка при сохранении model_info.json для версии {version}: {e}")
        return False


def model_exists_for_version(version: str) -> bool:
    """
    Проверяет, существует ли обученная модель для указанной версии
    """
    model_path = os.path.join(MODELS_DIR, version, "secret_detector_model.pkl")
    vectorizer_path = os.path.join(MODELS_DIR, version, "vectorizer.pkl")
    return os.path.exists(model_path) and os.path.exists(vectorizer_path)


def check_and_train_missing_models():
    """
    Проверяет все версии датасетов и обучает недостающие модели.
    Вызывается при запуске сервиса.
    """
    logger.info("Проверка версий датасетов и моделей...")
    
    dataset_versions = get_all_dataset_versions()
    if not dataset_versions:
        logger.warning("Не найдено ни одной версии датасетов")
        return
    
    logger.info(f"Найдено версий датасетов: {len(dataset_versions)}")
    
    for version in dataset_versions:
        logger.info(f"Проверка версии {version}...")
        
        # Убеждаемся, что датасеты распакованы
        if not ensure_datasets_extracted(version):
            logger.error(f"Не удалось подготовить датасеты для версии {version}, пропускаю")
            continue
        
        # Проверяем наличие модели
        if model_exists_for_version(version):
            logger.info(f"Модель для версии {version} уже существует")
        else:
            logger.info(f"Модель для версии {version} не найдена, начинаю обучение...")
            try:
                from app.model_loader import SecretClassifier
                classifier = SecretClassifier(version=version, console_mode=False)
                logger.info(f"Модель для версии {version} успешно обучена")
            except Exception as e:
                logger.error(f"Ошибка при обучении модели для версии {version}: {e}")
                import traceback
                traceback.print_exc()
    
    # Устанавливаем текущую версию, если файла нет
    if not os.path.exists(CURRENT_VERSION_FILE):
        latest_version = get_current_model_version()
        if latest_version:
            set_current_model_version(latest_version)
    
    logger.info("Проверка версий завершена")


def get_models_info() -> dict:
    """
    Получает информацию о всех моделях и датасетах
    Возвращает информацию о версиях, какие модели обучены, какие нет
    """
    result = {
        "datasets": [],
        "models": [],
        "current_version": get_current_model_version(),
        "missing_models": []  # Версии датасетов без моделей
    }
    
    # Получаем все версии датасетов
    dataset_versions = get_all_dataset_versions()
    
    for version in dataset_versions:
        dataset_info = {
            "version": version,
            "description": get_dataset_description(version),
            "has_secrets_file": os.path.exists(os.path.join(DATASETS_DIR, version, "Dataset_Secrets.txt")),
            "has_non_secrets_file": os.path.exists(os.path.join(DATASETS_DIR, version, "Dataset_NonSecrets.txt")),
            "has_zip": os.path.exists(os.path.join(DATASETS_DIR, version, "Datasets.zip"))
        }
        result["datasets"].append(dataset_info)
        
        # Проверяем наличие модели
        model_exists = model_exists_for_version(version)
        model_info = None
        
        if model_exists:
            # Читаем model_info.json если есть
            model_info_path = os.path.join(MODELS_DIR, version, "model_info.json")
            if os.path.exists(model_info_path):
                try:
                    with open(model_info_path, 'r', encoding='utf-8') as f:
                        model_info = json.load(f)
                except Exception as e:
                    logger.error(f"Ошибка чтения model_info.json для {version}: {e}")
                    model_info = {"version": version, "error": "Не удалось прочитать model_info.json"}
            else:
                model_info = {"version": version, "note": "model_info.json не найден"}
        else:
            result["missing_models"].append(version)
            model_info = {"version": version, "status": "not_trained"}
        
        if model_info:
            result["models"].append(model_info)
    
    return result


def upload_dataset_version(version: str, zip_file_path: str, description: str) -> bool:
    """
    Загружает новую версию датасетов
    Создает папку версии, копирует zip, распаковывает, создает description.txt
    """
    try:
        # Валидация версии
        if not re.match(r'^v\d+\.\d+$', version):
            raise ValueError(f"Неверный формат версии: {version}. Ожидается формат vX.Y")
        
        # Создаем папку версии
        version_dir = os.path.join(DATASETS_DIR, version)
        os.makedirs(version_dir, exist_ok=True)
        
        # Копируем zip файл
        target_zip = os.path.join(version_dir, "Datasets.zip")
        import shutil
        shutil.copy2(zip_file_path, target_zip)
        
        # Распаковываем
        if not ensure_datasets_extracted(version):
            raise Exception(f"Не удалось распаковать Datasets.zip для версии {version}")
        
        # Создаем description.txt
        description_file = os.path.join(version_dir, "description.txt")
        with open(description_file, 'w', encoding='utf-8') as f:
            f.write(description)
        
        logger.info(f"Версия датасетов {version} успешно загружена")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка загрузки версии датасетов {version}: {e}")
        raise


def train_missing_models() -> dict:
    """
    Обучает модели для всех версий датасетов, для которых нет моделей
    Возвращает результат обучения
    """
    result = {
        "success": True,
        "trained": [],
        "failed": [],
        "errors": []
    }
    
    dataset_versions = get_all_dataset_versions()
    
    for version in dataset_versions:
        # Проверяем наличие модели
        if model_exists_for_version(version):
            continue
        
        # Убеждаемся, что датасеты распакованы
        if not ensure_datasets_extracted(version):
            result["failed"].append(version)
            result["errors"].append(f"Не удалось подготовить датасеты для версии {version}")
            result["success"] = False
            continue
        
        # Обучаем модель
        try:
            from app.model_loader import SecretClassifier
            classifier = SecretClassifier(version=version, console_mode=False)
            result["trained"].append(version)
            logger.info(f"Модель для версии {version} успешно обучена")
        except Exception as e:
            result["failed"].append(version)
            result["errors"].append(f"Ошибка обучения модели для версии {version}: {str(e)}")
            result["success"] = False
            logger.error(f"Ошибка при обучении модели для версии {version}: {e}")
    
    return result


def validate_model_version(version: str) -> Tuple[bool, str]:
    """
    Валидирует версию модели - проверяет существование и целостность файлов
    Возвращает (is_valid, error_message)
    """
    if not re.match(r'^v\d+\.\d+$', version):
        return False, f"Неверный формат версии: {version}. Ожидается формат vX.Y"
    
    model_path = os.path.join(MODELS_DIR, version, "secret_detector_model.pkl")
    vectorizer_path = os.path.join(MODELS_DIR, version, "vectorizer.pkl")
    
    if not os.path.exists(model_path):
        return False, f"Файл модели не найден: {model_path}"
    
    if not os.path.exists(vectorizer_path):
        return False, f"Файл векторизатора не найден: {vectorizer_path}"
    
    # Проверяем, что файлы можно загрузить
    try:
        import joblib
        joblib.load(model_path)
        joblib.load(vectorizer_path)
    except Exception as e:
        return False, f"Файлы модели повреждены: {str(e)}"
    
    return True, ""


def switch_model_version(version: str) -> bool:
    """
    Меняет текущую версию модели
    Валидирует версию перед сменой
    """
    is_valid, error = validate_model_version(version)
    if not is_valid:
        raise ValueError(error)
    
    return set_current_model_version(version)

