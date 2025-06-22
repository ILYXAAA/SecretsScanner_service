import os
import time
import joblib
import random
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pickle
import logging
from logging.handlers import RotatingFileHandler

# Setup logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('secrets_scanner_service.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("model_loader")

class SecretClassifier:
    _instance = None
    model = None
    vectorizer = None

    MODEL_PATH = "Model/secret_detector_model.pkl"
    VECTORIZER_PATH = "Model/vectorizer.pkl"
    SECRETS_DATASET = "Datasets/Dataset_Secrets.txt"
    NOT_SECRETS_DATASET = "Datasets/Dataset_NonSecrets.txt"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_or_train_model()
        return cls._instance

    def _load_or_train_model(self):
        start_time = time.time()

        if os.path.exists(self.MODEL_PATH) and os.path.exists(self.VECTORIZER_PATH):
            self.model = joblib.load(self.MODEL_PATH)
            self.vectorizer = joblib.load(self.VECTORIZER_PATH)
            logger.info(f"Модель и векторизатор загружены за {(time.time() - start_time):.2f} сек.")
        else:
            logger.warning(f"Файлы модели не найдены, начинаю обучение.")
            self._train_model()
            logger.info(f"Модель обучена и сохранена за {(time.time() - start_time):.2f} сек.")

    def _train_model(self):
        """Обучение модели"""
        with open(self.SECRETS_DATASET, "r", encoding="utf-8") as f:
            secrets = f.read().splitlines()

        with open(self.NOT_SECRETS_DATASET, "r", encoding="utf-8") as f:
            non_secrets = f.read().splitlines()

        X = secrets + non_secrets
        y = [1] * len(secrets) + [0] * len(non_secrets)

        combined = list(zip(X, y))
        random.shuffle(combined)
        X, y = zip(*combined)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5))
        X_train_vec = self.vectorizer.fit_transform(X_train)

        self.model = LogisticRegression(max_iter=1000)
        self.model.fit(X_train_vec, y_train)

        # Ensure directories exist
        os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)
        
        joblib.dump(self.model, self.MODEL_PATH)
        joblib.dump(self.vectorizer, self.VECTORIZER_PATH)

    def get_model_memory_usage(self):
        """Get accurate memory usage of loaded model components"""
        memory_info = {}
        
        if self.model is not None:
            # Serialize model to measure size
            model_bytes = pickle.dumps(self.model)
            memory_info['model_mb'] = len(model_bytes) / (1024 * 1024)
        
        if self.vectorizer is not None:
            # Serialize vectorizer to measure size
            vectorizer_bytes = pickle.dumps(self.vectorizer)
            memory_info['vectorizer_mb'] = len(vectorizer_bytes) / (1024 * 1024)
            
            # Additional vectorizer details
            if hasattr(self.vectorizer, 'vocabulary_'):
                memory_info['vocabulary_size'] = len(self.vectorizer.vocabulary_)
        
        memory_info['total_mb'] = memory_info.get('model_mb', 0) + memory_info.get('vectorizer_mb', 0)
        
        return memory_info

    def filter_secrets(self, secrets: list[dict]) -> list[dict]:
        classification_start = time.time()
        """
        Классифицирует каждый элемент словаря в списке secrets по полю "secret".
        Заполняет поле "severity":
        - "High" для уверенных секретов и неуверенных
        - "Potential" для не секретов с высокой уверенностью
        
        Возвращает список словарей с обновленным полем "severity".
        """
        if not secrets:
            return secrets
            
        # Извлекаем строки для предсказания
        texts = [item.get("secret", "") for item in secrets]
        
        if not texts:
            return secrets

        try:
            X_vec = self.vectorizer.transform(texts)
            preds = self.model.predict(X_vec)
            probs = self.model.predict_proba(X_vec)

            for item, pred, proba in zip(secrets, preds, probs):
                if not item.get("severity"):  # Only update if not already set
                    confidence = proba[pred]
                    if pred == 1:
                        # Уверен что секрет
                        item["severity"] = "High"
                    else:
                        if confidence > 0.80:
                            # Уверен что не секрет
                            item["severity"] = "Potential"
                        else:
                            # Не уверен
                            item["severity"] = "High"
        except Exception as e:
            logger.error(f"Ошибка классификации: {e}")
            # Fallback: mark all as High severity
            for item in secrets:
                if not item.get("severity"):
                    item["severity"] = "High"

        classification_time = time.time() - classification_start
        logger.info(f"Классификация завершена для {len(secrets)} элементов (время: {classification_time:.2f}с)")
        return secrets

# Глобальная функция для использования в FastAPI
def get_model_instance():
    """Получить экземпляр модели (thread-safe)"""
    return SecretClassifier()

# Функция для использования в отдельных процессах
def filter_secrets_in_process(secrets_list: list[dict]) -> list[dict]:
    """Функция для фильтрации секретов в отдельном процессе"""
    try:
        classifier = SecretClassifier()
        return classifier.filter_secrets(secrets_list)
    except Exception as e:
        logger.error(f"Ошибка в процессе классификации: {e}")
        # Fallback: mark all as High severity
        for item in secrets_list:
            if not item.get("severity"):
                item["severity"] = "High"
        return secrets_list