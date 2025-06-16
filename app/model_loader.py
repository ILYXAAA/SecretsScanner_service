import os
import time
import joblib
import random
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

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
            print(f"✅ Модель и векторизатор загружены за {(time.time() - start_time):.2f} сек.")
        else:
            print(f"Файлы модели не найдены, начинаю обучение.")
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

            joblib.dump(self.model, self.MODEL_PATH)
            joblib.dump(self.vectorizer, self.VECTORIZER_PATH)
            print(f"✅ Модель обучена и сохранена за {(time.time() - start_time):.2f} сек.")

    def filter_secrets(self, secrets: list[dict]) -> list[dict]:
        """
        Классифицирует каждый элемент словаря в списке secrets по полю "secret" (или "context").
        Заполняет поле "severity":
        - "High" для уверенных секретов и неуверенных
        - "Potential" для не секретов с высокой уверенностью
        
        Возвращает список словарей с обновленным полем "severity".
        """
        # Извлекаем строки для предсказания, например, по ключу "secret"
        texts = [item.get("secret", "") for item in secrets]

        X_vec = self.vectorizer.transform(texts)
        preds = self.model.predict(X_vec)
        probs = self.model.predict_proba(X_vec)

        for item, pred, proba in zip(secrets, preds, probs):
            if not item["severity"]:
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
            else:
                item["severity"] = "High"
        print(f"✅ Сканирование завершено")
        return secrets

# Для использования в FastAPI
def get_model_instance():
    return SecretClassifier()

