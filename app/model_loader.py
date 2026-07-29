import os
import time
import joblib
import random
import csv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import pickle
import logging
from logging.handlers import RotatingFileHandler
from app.model_version_manager import (
    get_current_model_version, ensure_datasets_extracted,
    get_dataset_description, save_model_info
)

# Setup logging function
def setup_logging(console_mode=False):
    # log_file = '../secrets_scanner_service.log' if console_mode else 'secrets_scanner_service.log'
    
    # logging.basicConfig(
    #     level=logging.INFO,
    #     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    #     handlers=[
    #         RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
    #         logging.StreamHandler()
    #     ]
    # )
    return logging.getLogger("model_loader")

# Default logger for import mode
logger = setup_logging(console_mode=False)


class SecretClassifier:
    _instances = {}  # Храним экземпляры по версиям
    model = None
    vectorizer = None
    version = None

    def __init__(self, version=None, console_mode=False):
        # Определяем версию
        if version is None:
            version = get_current_model_version()
            if version is None:
                raise ValueError("Не удалось определить версию модели")
        
        self.version = version
        
        # Убеждаемся, что датасеты распакованы
        if not console_mode:
            ensure_datasets_extracted(version)
        
        # Определяем пути в зависимости от режима запуска
        if console_mode:
            self.MODEL_PATH = f"../Model/{version}/secret_detector_model.pkl"
            self.VECTORIZER_PATH = f"../Model/{version}/vectorizer.pkl"
            self.SECRETS_DATASET = f"../Datasets/{version}/Dataset_Secrets.txt"
            self.NOT_SECRETS_DATASET = f"../Datasets/{version}/Dataset_NonSecrets.txt"
            self.TEST_CSV_PATH = "../TestModel/TestModel.csv"
        else:
            self.MODEL_PATH = f"Model/{version}/secret_detector_model.pkl"
            self.VECTORIZER_PATH = f"Model/{version}/vectorizer.pkl"
            self.SECRETS_DATASET = f"Datasets/{version}/Dataset_Secrets.txt"
            self.NOT_SECRETS_DATASET = f"Datasets/{version}/Dataset_NonSecrets.txt"
            self.TEST_CSV_PATH = "TestModel/TestModel.csv"

    def __new__(cls, version=None, console_mode=False):
        # Определяем версию для ключа
        if version is None:
            version = get_current_model_version()
            if version is None:
                raise ValueError("Не удалось определить версию модели")
        
        # Используем версию как ключ для Singleton
        instance_key = f"{version}_{console_mode}"
        
        if instance_key not in cls._instances:
            cls._instances[instance_key] = super().__new__(cls)
            cls._instances[instance_key].__init__(version, console_mode)
            cls._instances[instance_key]._load_or_train_model()
        
        return cls._instances[instance_key]

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

        secrets_size = len(secrets)
        non_secrets_size = len(non_secrets)

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
        
        # Сохраняем информацию о модели
        description = get_dataset_description(self.version)
        save_model_info(self.version, secrets_size, non_secrets_size, description)

    def retrain_model(self):
        """Переобучение модели с нуля"""
        print("🔄 Начинаю переобучение модели...")
        start_time = time.time()
        
        # Удаляем старые файлы модели если они есть
        if os.path.exists(self.MODEL_PATH):
            os.remove(self.MODEL_PATH)
        if os.path.exists(self.VECTORIZER_PATH):
            os.remove(self.VECTORIZER_PATH)
            
        self._train_model()
        
        training_time = time.time() - start_time
        print(f"✅ Модель успешно переобучена за {training_time:.2f} секунд")
        
        # Тестируем модель на тестовых данных
        self._evaluate_model(use_internal_test=True)

    def _evaluate_model(self, use_internal_test=True, csv_path=None):
        """Оценка модели на тестовых данных или внешнем CSV файле"""
        start_time = time.time()
        
        if csv_path and os.path.exists(csv_path):
            # Используем внешний CSV файл
            print(f"📁 Загружаю тестовый файл: {csv_path}")
            
            try:
                test_data = []
                with open(csv_path, 'r', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        secret_value = row.get('secret_value', '') or ''
                        secret_type = row.get('secret_type', '') or ''
                        
                        # Безопасно обрабатываем значения
                        if secret_value:
                            secret_value = secret_value.strip()
                        if secret_type:
                            secret_type = secret_type.strip()
                        
                        if secret_value and secret_type:
                            # Конвертируем строковую метку в числовую
                            true_label = 1 if secret_type.lower() == 'secret' else 0
                            test_data.append({
                                'text': secret_value,
                                'true_label': true_label,
                                'true_label_str': secret_type
                            })
                
                if not test_data:
                    print("❌ В CSV файле не найдены данные для тестирования!")
                    return
                    
                X = [item['text'] for item in test_data]
                y = [item['true_label'] for item in test_data]
                y_str = [item['true_label_str'] for item in test_data]
                
                print(f"📊 Загружено {len(test_data)} тестовых примеров")
                
            except Exception as e:
                print(f"❌ Ошибка при чтении CSV файла: {e}")
                return
                
        elif use_internal_test:
            # Используем внутренние датасеты
            try:
                with open(self.SECRETS_DATASET, "r", encoding="utf-8") as f:
                    secrets = f.read().splitlines()

                with open(self.NOT_SECRETS_DATASET, "r", encoding="utf-8") as f:
                    non_secrets = f.read().splitlines()

                X = secrets + non_secrets
                y = [1] * len(secrets) + [0] * len(non_secrets)
                y_str = ['Secret'] * len(secrets) + ['NotSecret'] * len(non_secrets)

                combined = list(zip(X, y, y_str))
                random.shuffle(combined)
                X, y, y_str = zip(*combined)

                X_train, X_test, y_train, y_test, y_str_train, y_str_test = train_test_split(
                    X, y, y_str, test_size=0.2, random_state=42)
                
                # Используем тестовые данные
                X = X_test
                y = y_test
                y_str = y_str_test
                
            except Exception as e:
                print(f"❌ Ошибка при чтении датасетов: {e}")
                return
        else:
            print("❌ Не указан источник данных для тестирования!")
            return
        
        try:
            # Векторизованное предсказание (быстро!)
            print("🔄 Обработка данных...")
            X_vec = self.vectorizer.transform(X)
            y_pred = self.model.predict(X_vec)
            y_proba = self.model.predict_proba(X_vec)
            
            processing_time = time.time() - start_time
            
            # Подсчитываем метрики
            accuracy = accuracy_score(y, y_pred)
            precision = precision_score(y, y_pred, zero_division=0)
            recall = recall_score(y, y_pred, zero_division=0)
            f1 = f1_score(y, y_pred, zero_division=0)
            
            # Статистика по классам
            secrets_count = sum(1 for label in y if label == 1)
            non_secrets_count = len(y) - secrets_count
            correct_predictions = sum(1 for true, pred in zip(y, y_pred) if true == pred)
            
            # Ошибки
            false_positives = sum(1 for true, pred in zip(y, y_pred) if true == 0 and pred == 1)
            false_negatives = sum(1 for true, pred in zip(y, y_pred) if true == 1 and pred == 0)
            
            # Собираем неправильные предсказания
            wrong_predictions = []
            for i, (text, true_label, pred_label, proba) in enumerate(zip(X, y, y_pred, y_proba)):
                if true_label != pred_label:
                    confidence = proba[1]  # Вероятность класса "Secret"
                    wrong_predictions.append({
                        'secret': text,
                        'expected': y_str[i],
                        'prediction': 'Secret' if pred_label == 1 else 'NotSecret',
                        'confidence': round(confidence, 3)
                    })
            
            # Выводим результаты
            if csv_path:
                print(f"\n✅ РЕЗУЛЬТАТЫ АВТОМАТИЧЕСКОЙ ПРОВЕРКИ")
                print("=" * 50)
            else:
                print(f"\n📊 Метрики модели на тестовых данных:")
                print("-" * 40)
                
            print(f"⏱️  Время выполнения: {processing_time:.2f} секунд")
            print(f"📊 Общее количество обработанных записей: {len(y)}")
            print(f"🔴 Секреты в тестовом наборе: {secrets_count}")
            print(f"🟢 Не-секреты в тестовом наборе: {non_secrets_count}")
            print(f"✅ Правильно размечено: {correct_predictions} из {len(y)}")
            print(f"🎯 Точность (Accuracy): {accuracy:.1%} ({accuracy:.3f})")
            print(f"📈 Precision: {precision:.1%} ({precision:.3f})")
            print(f"🔍 Recall: {recall:.1%} ({recall:.3f})")
            print(f"⚖️  F1-Score: {f1:.1%} ({f1:.3f})")
            print(f"⚡ Средняя скорость: {len(y)/processing_time:.1f} предсказаний/сек")
            
            print(f"\n🔍 ДЕТАЛЬНАЯ СТАТИСТИКА ОШИБОК:")
            print(f"   False Positives (неправильно определены как секреты): {false_positives}")
            print(f"   False Negatives (пропущенные секреты): {false_negatives}")
            
            # Сохраняем неправильные предсказания в CSV (только для внешнего тестирования)
            if csv_path and wrong_predictions:
                wrong_csv_path = "../TestModel/wrong_secrets.csv"
                try:
                    os.makedirs(os.path.dirname(wrong_csv_path), exist_ok=True)
                    
                    with open(wrong_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ['secret', 'expected', 'prediction', 'confidence']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(wrong_predictions)
                    
                    print(f"💾 Неправильные предсказания сохранены в: {wrong_csv_path}")
                    print(f"   Количество ошибок: {len(wrong_predictions)}")
                    
                except Exception as e:
                    print(f"❌ Ошибка при сохранении файла с ошибками: {e}")
            elif csv_path and not wrong_predictions:
                print("🎉 Все предсказания были правильными!")
            
        except Exception as e:
            print(f"❌ Ошибка при оценке модели: {e}")
            import traceback
            traceback.print_exc()

    def automatic_test_from_csv(self):
        """Автоматическое тестирование модели на CSV файле"""
        print("\n🤖 АВТОМАТИЧЕСКАЯ ПРОВЕРКА МОДЕЛИ")
        print("-" * 40)
        
        if not os.path.exists(self.TEST_CSV_PATH):
            print(f"❌ Файл {self.TEST_CSV_PATH} не найден!")
            return
            
        # Используем улучшенную функцию _evaluate_model
        self._evaluate_model(use_internal_test=False, csv_path=self.TEST_CSV_PATH)

    def get_model_info(self):
        """Получить информацию о модели и датасетах"""
        info = {}
        
        # Информация о датасетах
        try:
            if os.path.exists(self.SECRETS_DATASET):
                with open(self.SECRETS_DATASET, "r", encoding="utf-8") as f:
                    secrets_count = len(f.read().splitlines())
                info['secrets_dataset_size'] = secrets_count
            else:
                info['secrets_dataset_size'] = 0
                
            if os.path.exists(self.NOT_SECRETS_DATASET):
                with open(self.NOT_SECRETS_DATASET, "r", encoding="utf-8") as f:
                    non_secrets_count = len(f.read().splitlines())
                info['non_secrets_dataset_size'] = non_secrets_count
            else:
                info['non_secrets_dataset_size'] = 0
                
            info['total_dataset_size'] = info.get('secrets_dataset_size', 0) + info.get('non_secrets_dataset_size', 0)
        except Exception as e:
            logger.error(f"Ошибка при чтении датасетов: {e}")
        
        # Информация о модели
        if self.model is not None:
            info['model_type'] = type(self.model).__name__
            if hasattr(self.model, 'C'):
                info['model_C'] = self.model.C
            if hasattr(self.model, 'max_iter'):
                info['model_max_iter'] = self.model.max_iter
                
        # Информация о векторизаторе
        if self.vectorizer is not None:
            info['vectorizer_type'] = type(self.vectorizer).__name__
            info['vectorizer_analyzer'] = getattr(self.vectorizer, 'analyzer', 'unknown')
            info['vectorizer_ngram_range'] = getattr(self.vectorizer, 'ngram_range', 'unknown')
            if hasattr(self.vectorizer, 'vocabulary_'):
                info['vocabulary_size'] = len(self.vectorizer.vocabulary_)
        
        # Размер модели в памяти
        memory_info = self.get_model_memory_usage()
        info.update(memory_info)
        
        return info

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

    def predict_single(self, text: str, context: str = None):
        """Предсказание для одной строки с возможностью использования контекста"""
        if not text.strip():
            return None
            
        start_time = time.time()
        
        try:
            # Предсказание для основного текста
            X_vec = self.vectorizer.transform([text])
            pred_text = self.model.predict(X_vec)[0]
            proba_text = self.model.predict_proba(X_vec)[0]
            confidence_text = proba_text[1]
            
            # Если есть контекст, делаем предсказание и для него
            if context and context.strip():
                X_context_vec = self.vectorizer.transform([context])
                pred_context = self.model.predict(X_context_vec)[0]
                proba_context = self.model.predict_proba(X_context_vec)[0]
                confidence_context = proba_context[1]
                
                # Усредняем confidence
                secret_weight = 1.0
                context_weight = 0.8
                confidence = (confidence_text * secret_weight + confidence_context * context_weight) / (secret_weight + context_weight)
                # Финальное предсказание основываем на усредненной уверенности
                pred = int(confidence > 0.5)
                
                prediction_details = {
                    'text_prediction': bool(pred_text),
                    'text_confidence': round(confidence_text, 3),
                    'context_prediction': bool(pred_context),
                    'context_confidence': round(confidence_context, 3),
                    'averaged_confidence': True
                }
            else:
                # Используем только предсказание по тексту
                confidence = confidence_text
                pred = pred_text
                prediction_details = {
                    'text_prediction': bool(pred_text),
                    'text_confidence': round(confidence_text, 3),
                    'context_prediction': None,
                    'context_confidence': None,
                    'averaged_confidence': False
                }
            
            processing_time = time.time() - start_time

            if confidence > 0.7:
                severity = "High"
            else:
                severity = "Potential"

            return {
                'text': text,
                'context': context,
                'is_secret': bool(pred),
                'confidence': round(confidence, 3),
                'severity': severity,
                'processing_time_ms': round(processing_time * 1000, 2),
                'prediction_details': prediction_details
            }
            
        except Exception as e:
            logger.error(f"Ошибка при предсказании: {e}")
            return {
                'text': text,
                'context': context,
                'error': str(e)
            }

    def filter_secrets(self, ProjectName, secrets: list[dict], worker_instance=None) -> list[dict]:
        classification_start = time.time()
        """
        Классифицирует каждый элемент словаря в списке secrets по полям "secret" и "context".
        """
        if not secrets:
            return secrets

        secret_texts = [item.get("secret", "") for item in secrets]
        context_texts = [item.get("context", "") for item in secrets]

        if not secret_texts:
            return secrets

        try:
            total_items = len(secrets)
            logger.info(f"[{ProjectName}] Начинаю ML классификацию {total_items} элементов")

            X_secret_vec = self.vectorizer.transform(secret_texts)
            preds_secret = self.model.predict(X_secret_vec)
            probs_secret = self.model.predict_proba(X_secret_vec)

            if worker_instance:
                progress = 30
                worker_instance.send_heartbeat_if_needed(
                    "ml_validation", 10, progress, f"Обработано {len(secret_texts)} секретов",
                )

            context_predictions = []
            context_probabilities = []
            non_empty_contexts = [ctx if ctx and ctx.strip() else None for ctx in context_texts]

            if any(ctx is not None for ctx in non_empty_contexts):
                contexts_to_predict = [ctx for ctx in non_empty_contexts if ctx is not None]

                if contexts_to_predict:
                    X_context_vec = self.vectorizer.transform(contexts_to_predict)
                    context_preds = self.model.predict(X_context_vec)
                    context_probs = self.model.predict_proba(X_context_vec)

                    if worker_instance:
                        progress = 60
                        worker_instance.send_heartbeat_if_needed(
                            "ml_validation", 10, progress,
                            f"Обработано {len(contexts_to_predict)} контекстов",
                        )

                    context_idx = 0
                    for ctx in non_empty_contexts:
                        if ctx is not None:
                            context_predictions.append(context_preds[context_idx])
                            context_probabilities.append(context_probs[context_idx])
                            context_idx += 1
                        else:
                            context_predictions.append(None)
                            context_probabilities.append(None)
                else:
                    context_predictions = [None] * len(secrets)
                    context_probabilities = [None] * len(secrets)
            else:
                context_predictions = [None] * len(secrets)
                context_probabilities = [None] * len(secrets)

            processed_secrets = 0
            for i, (item, pred_secret, proba_secret) in enumerate(zip(secrets, preds_secret, probs_secret)):
                progress = 60 + int((processed_secrets / total_items) * 40) if total_items > 0 else 60
                progress_detail = f"Проанализировано {processed_secrets} из {total_items} результатов"

                if worker_instance:
                    worker_instance.send_heartbeat_if_needed("ml_validation", 10, progress, progress_detail)

                    if hasattr(worker_instance, 'current_task') and worker_instance.current_task:
                        if worker_instance.check_task_timeout(worker_instance.current_task):
                            raise Exception("Task timeout during ML validation")

                confidence_secret = proba_secret[1]
                pred_context = context_predictions[i] if i < len(context_predictions) else None
                proba_context = context_probabilities[i] if i < len(context_probabilities) else None

                item["secret_confidence"] = round(confidence_secret, 3)
                item["secret_prediction"] = bool(pred_secret)

                if pred_context is not None and proba_context is not None:
                    confidence_context = proba_context[1]
                    item["context_confidence"] = round(confidence_context, 3)
                    item["context_prediction"] = bool(pred_context)

                    secret_weight = 1.0
                    context_weight = 0.8
                    final_confidence = (
                        confidence_secret * secret_weight + confidence_context * context_weight
                    ) / (secret_weight + context_weight)
                    item["confidence_averaged"] = True
                else:
                    final_confidence = confidence_secret
                    item["context_confidence"] = None
                    item["context_prediction"] = None
                    item["confidence_averaged"] = False

                item["confidence"] = round(final_confidence, 2)
                item["severity"] = "High" if final_confidence > 0.7 else "Potential"

                processed_secrets += 1

            if worker_instance:
                worker_instance.send_heartbeat(
                    "ml_validation", force=True, progress=100,
                    progress_detail=f"Обработано {total_items} секретов",
                )

        except Exception as e:
            logger.error(f"Ошибка классификации: {e}")
            for item in secrets:
                item["confidence"] = 1.00
                if not item.get("severity"):
                    item["severity"] = "High"

        classification_time = time.time() - classification_start
        logger.info(
            f"[{ProjectName}] Классификация завершена для {len(secrets)} элементов "
            f"(время: {classification_time:.2f}с)"
        )
        return secrets

# Глобальная функция для использования в FastAPI
def get_model_instance(version=None):
    """Получить экземпляр модели (thread-safe)
    
    Args:
        version: Версия модели. Если None, используется текущая версия из current_version.txt
    """
    return SecretClassifier(version=version, console_mode=False)

# Функция для использования в отдельных процессах
def filter_secrets_in_process(ProjectName, secrets_list: list[dict], worker_instance=None) -> list[dict]:
    """Функция для фильтрации секретов в отдельном процессе
    
    Использует версию модели из worker_instance, чтобы каждый воркер работал
    с той версией модели, с которой он запустился.
    """
    try:
        # Получаем версию модели из воркера, если он передан
        model_version = None
        if worker_instance and hasattr(worker_instance, 'model_version') and worker_instance.model_version:
            model_version = worker_instance.model_version
        
        # Используем версию модели воркера, а не актуальную из файла
        classifier = get_model_instance(version=model_version)
        return classifier.filter_secrets(ProjectName, secrets_list, worker_instance)
    except Exception as e:
        logger.error(f"Ошибка в процессе классификации: {e}")
        # Fallback: mark all as High severity
        for item in secrets_list:
            if not item.get("severity"):
                item["severity"] = "High"
        return secrets_list


def show_menu():
    """Показать меню консольного менеджера"""
    print("\n" + "="*50)
    print("🤖 МЕНЕДЖЕР МОДЕЛИ SECRETS CLASSIFIER")
    print("="*50)
    print("1. 🔄 Переобучить модель")
    print("2. 📊 Показать параметры модели")
    print("3. 🧪 Протестировать модель")
    print("4. 🤖 Автоматическая проверка")
    print("5. 🚪 Выход")
    print("="*50)


def show_model_info(classifier):
    """Показать информацию о модели"""
    print("\n📋 ИНФОРМАЦИЯ О МОДЕЛИ")
    print("-" * 30)
    
    info = classifier.get_model_info()
    
    # Информация о датасетах
    print(f"📁 Датасеты:")
    print(f"   • Секреты: {info.get('secrets_dataset_size', 'N/A')} примеров")
    print(f"   • Не секреты: {info.get('non_secrets_dataset_size', 'N/A')} примеров")
    print(f"   • Общий размер: {info.get('total_dataset_size', 'N/A')} примеров")
    
    # Информация о модели
    print(f"\n🤖 Модель:")
    print(f"   • Тип: {info.get('model_type', 'N/A')}")
    if 'model_C' in info:
        print(f"   • Параметр C: {info['model_C']}")
    if 'model_max_iter' in info:
        print(f"   • Макс. итераций: {info['model_max_iter']}")
    
    # Информация о векторизаторе
    print(f"\n🔤 Векторизатор:")
    print(f"   • Тип: {info.get('vectorizer_type', 'N/A')}")
    print(f"   • Анализатор: {info.get('vectorizer_analyzer', 'N/A')}")
    print(f"   • N-gram диапазон: {info.get('vectorizer_ngram_range', 'N/A')}")
    print(f"   • Размер словаря: {info.get('vocabulary_size', 'N/A')}")
    
    # Информация о памяти
    print(f"\n💾 Использование памяти:")
    print(f"   • Модель: {info.get('model_mb', 0):.2f} МБ")
    print(f"   • Векторизатор: {info.get('vectorizer_mb', 0):.2f} МБ")
    print(f"   • Общий размер: {info.get('total_mb', 0):.2f} МБ")


def test_model(classifier):
    """Интерактивное тестирование модели"""
    print("\n🧪 ТЕСТИРОВАНИЕ МОДЕЛИ")
    print("-" * 30)
    print("Введите строки для тестирования (пустая строка для выхода):")
    print("Опционально можете добавить контекст после основного текста.")
    print("-" * 50)
    
    while True:
        try:
            text = input("\n> Введите текст: ").strip()
            
            if not text:
                print("👋 Выход из режима тестирования.")
                break
            
            context = input("> Введите контекст (опционально): ").strip()
            if not context:
                context = None
                
            result = classifier.predict_single(text, context)
            
            if result is None:
                print("⚠️  Пустая строка, попробуйте еще раз.")
                continue
                
            if 'error' in result:
                print(f"❌ Ошибка: {result['error']}")
                continue
            
            print(f"\n📊 Результат:")
            print(f"   🎯 Результат: {'🔴 СЕКРЕТ' if result['is_secret'] else '🟢 НЕ СЕКРЕТ'}")
            print(f"   📈 Итоговая уверенность: {result['confidence']:.1%}")
            print(f"   ⚡ Серьезность: {result['severity']}")
            print(f"   ⏱️  Время обработки: {result['processing_time_ms']} мс")
            
            # Детали предсказаний
            details = result.get('prediction_details', {})
            if details.get('averaged_confidence'):
                print(f"\n📋 Детали предсказаний:")
                print(f"   • Текст: {details['text_confidence']:.1%} ({'секрет' if details['text_prediction'] else 'не секрет'})")
                print(f"   • Контекст: {details['context_confidence']:.1%} ({'секрет' if details['context_prediction'] else 'не секрет'})")
                print(f"   • Использовано усреднение confidence")
            else:
                print(f"\n📋 Детали: использован только анализ основного текста")
            
        except KeyboardInterrupt:
            print("\n👋 Выход из режима тестирования.")
            break
        except Exception as e:
            print(f"❌ Ошибка: {e}")


def console_manager():
    """Основная функция консольного менеджера"""
    # Настраиваем логирование для консольного режима
    global logger
    logger = setup_logging(console_mode=True)
    
    print("🚀 Загрузка модели...")
    
    try:
        from app.model_version_manager import get_current_model_version
        version = get_current_model_version()
        if version:
            print(f"📦 Используется версия модели: {version}")
        classifier = SecretClassifier(version=version, console_mode=True)
        print("✅ Модель успешно загружена!")
    except Exception as e:
        print(f"❌ Ошибка при загрузке модели: {e}")
        return
    
    while True:
        show_menu()
        
        try:
            choice = input("\n🔸 Выберите пункт (1-5): ").strip()
            
            if choice == '1':
                confirm = input("⚠️  Вы уверены что хотите переобучить модель? (y/n): ").strip().lower()
                if confirm in ['y', 'yes', 'да', 'д']:
                    classifier.retrain_model()
                else:
                    print("❌ Переобучение отменено.")
                    
            elif choice == '2':
                show_model_info(classifier)
                
            elif choice == '3':
                test_model(classifier)
                
            elif choice == '4':
                classifier.automatic_test_from_csv()
                
            elif choice == '5':
                print("👋 До свидания!")
                break
                
            else:
                print("❌ Неверный выбор. Попробуйте еще раз.")
                
        except KeyboardInterrupt:
            print("\n👋 До свидания!")
            break
        except Exception as e:
            print(f"❌ Ошибка: {e}")


if __name__ == "__main__":
    console_manager()