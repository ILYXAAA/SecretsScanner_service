#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализатор качества датасетов для обучения классификатора секретов
Анализирует датасеты секретов и не-секретов на основе лучших практик ML

Автор: AI Assistant
Версия: 2.0 - с прогресс-барами и автоисправлением
"""

import os
import re
import yaml
import json
import hashlib
import statistics
import shutil
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Set
import difflib
from datetime import datetime

try:
    from tqdm import tqdm
except ImportError:
    print("Устанавливаю tqdm для отображения прогресса...")
    os.system("pip install tqdm")
    from tqdm import tqdm


class DatasetQualityAnalyzer:
    """
    Анализатор качества датасетов для детекции секретов
    """
    
    def __init__(self, rules_path: str, secrets_path: str, non_secrets_path: str):
        """
        Инициализация анализатора
        
        Args:
            rules_path: Путь к файлу с регулярными выражениями
            secrets_path: Путь к датасету с секретами
            non_secrets_path: Путь к датасету с не-секретами
        """
        self.rules_path = rules_path
        self.secrets_path = secrets_path
        self.non_secrets_path = non_secrets_path
        
        # Загружаем данные
        print("Загружаю правила...")
        self.rules = self._load_rules()
        
        print("Загружаю датасет секретов...")
        self.secrets = self._load_dataset(secrets_path)
        
        print("Загружаю датасет не-секретов...")
        self.non_secrets = self._load_dataset(non_secrets_path)
        
        print(f"Загружено: {len(self.secrets)} секретов, {len(self.non_secrets)} не-секретов")
        
        # Результаты анализа
        self.analysis_results = {}
        
        # Настройки для оптимизации больших датасетов
        # (убрали анализ похожих строк для производительности)
        
    def _load_rules(self) -> List[Dict]:
        """Загружает правила из YAML файла"""
        try:
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
            return rules if isinstance(rules, list) else []
        except Exception as e:
            print(f"Ошибка загрузки правил: {e}")
            return []
    
    def _load_dataset(self, path: str) -> List[str]:
        """Загружает датасет из файла"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = []
                for line in tqdm(f, desc=f"Читаю {os.path.basename(path)}"):
                    line = line.strip()
                    if line:
                        lines.append(line)
                return lines
        except Exception as e:
            print(f"Ошибка загрузки датасета {path}: {e}")
            return []
    
    def analyze_basic_statistics(self) -> Dict:
        """Анализ базовой статистики датасетов"""
        print("Анализирую базовую статистику...")
        
        stats = {
            'secrets_count': len(self.secrets),
            'non_secrets_count': len(self.non_secrets),
            'total_count': len(self.secrets) + len(self.non_secrets),
            'class_balance': len(self.secrets) / (len(self.secrets) + len(self.non_secrets)) if self.secrets or self.non_secrets else 0,
            'secrets_avg_length': statistics.mean([len(s) for s in self.secrets]) if self.secrets else 0,
            'non_secrets_avg_length': statistics.mean([len(s) for s in self.non_secrets]) if self.non_secrets else 0,
            'secrets_length_std': statistics.stdev([len(s) for s in self.secrets]) if len(self.secrets) > 1 else 0,
            'non_secrets_length_std': statistics.stdev([len(s) for s in self.non_secrets]) if len(self.non_secrets) > 1 else 0
        }
        
        self.analysis_results['basic_statistics'] = stats
        return stats
    
    def analyze_duplicates(self) -> Dict:
        """Анализ дубликатов в датасетах"""
        print("Анализирую дубликаты...")
        
        # Точные дубликаты с прогресс-баром
        print("  Подсчитываю дубликаты в секретах...")
        secrets_counts = Counter(tqdm(self.secrets, desc="Анализ секретов"))
        
        print("  Подсчитываю дубликаты в не-секретах...")
        non_secrets_counts = Counter(tqdm(self.non_secrets, desc="Анализ не-секретов"))
        
        secrets_duplicates = {k: v for k, v in secrets_counts.items() if v > 1}
        non_secrets_duplicates = {k: v for k, v in non_secrets_counts.items() if v > 1}
        
        # Пересечения между классами
        print("  Ищу пересечения между классами...")
        secrets_set = set(self.secrets)
        non_secrets_set = set(self.non_secrets)
        intersection = secrets_set & non_secrets_set
        
        # Убираем анализ похожих строк для производительности
        
        duplicates_analysis = {
            'secrets_exact_duplicates': len(secrets_duplicates),
            'non_secrets_exact_duplicates': len(non_secrets_duplicates),
            'cross_class_duplicates': len(intersection),
            'secrets_duplicate_ratio': len(secrets_duplicates) / len(self.secrets) if self.secrets else 0,
            'non_secrets_duplicate_ratio': len(non_secrets_duplicates) / len(self.non_secrets) if self.non_secrets else 0,
            'duplicate_examples': {
                'secrets': list(secrets_duplicates.keys())[:5],
                'non_secrets': list(non_secrets_duplicates.keys())[:5],
                'cross_class': list(intersection)[:5]
            },
            'secrets_duplicates_dict': secrets_duplicates,
            'non_secrets_duplicates_dict': non_secrets_duplicates,
            'cross_class_list': list(intersection)
        }
        
        self.analysis_results['duplicates'] = duplicates_analysis
        return duplicates_analysis
    
    def analyze_rule_coverage(self) -> Dict:
        """Анализ покрытия датасетов правилами"""
        print("Анализирую покрытие правилами...")
        
        rule_matches = defaultdict(lambda: {'secrets': 0, 'non_secrets': 0})
        uncovered_secrets = []
        uncovered_non_secrets = []
        
        # Компилируем регулярные выражения
        compiled_rules = []
        for rule in tqdm(self.rules, desc="Компилирую правила"):
            try:
                compiled_rules.append({
                    'id': rule['id'],
                    'pattern': re.compile(rule['pattern'], re.IGNORECASE),
                    'severity': rule.get('severity', 'UNKNOWN')
                })
            except re.error as e:
                print(f"Ошибка в регулярном выражении {rule['id']}: {e}")
        
        # Проверяем покрытие секретов
        for secret in tqdm(self.secrets, desc="Проверяю покрытие секретов"):
            matched = False
            for rule in compiled_rules:
                if rule['pattern'].search(secret):
                    rule_matches[rule['id']]['secrets'] += 1
                    matched = True
                    break  # Достаточно одного совпадения
            if not matched:
                uncovered_secrets.append(secret)
        
        # Проверяем покрытие не-секретов
        for non_secret in tqdm(self.non_secrets, desc="Проверяю покрытие не-секретов"):
            matched = False
            for rule in compiled_rules:
                if rule['pattern'].search(non_secret):
                    rule_matches[rule['id']]['non_secrets'] += 1
                    matched = True
                    break  # Достаточно одного совпадения
            if not matched:
                uncovered_non_secrets.append(non_secret)
        
        coverage_analysis = {
            'total_rules': len(compiled_rules),
            'rules_matching_secrets': len([r for r in rule_matches.values() if r['secrets'] > 0]),
            'rules_matching_non_secrets': len([r for r in rule_matches.values() if r['non_secrets'] > 0]),
            'secrets_coverage_ratio': (len(self.secrets) - len(uncovered_secrets)) / len(self.secrets) if self.secrets else 0,
            'non_secrets_coverage_ratio': (len(self.non_secrets) - len(uncovered_non_secrets)) / len(self.non_secrets) if self.non_secrets else 0,
            'uncovered_secrets_count': len(uncovered_secrets),
            'uncovered_non_secrets_count': len(uncovered_non_secrets),
            'rule_matches': dict(rule_matches),
            'uncovered_examples': {
                'secrets': uncovered_secrets[:10],
                'non_secrets': uncovered_non_secrets[:10]
            },
            'uncovered_secrets_list': uncovered_secrets,
            'uncovered_non_secrets_list': uncovered_non_secrets
        }
        
        self.analysis_results['rule_coverage'] = coverage_analysis
        return coverage_analysis
    
    def analyze_data_quality_issues(self) -> Dict:
        """Анализ проблем качества данных"""
        print("Анализирую проблемы качества данных...")
        
        issues = {
            'empty_strings': [],
            'too_short': [],
            'too_long': [],
            'non_printable_chars': [],
            'encoding_issues': [],
            'whitespace_only': [],
            'potential_test_data': []
        }
        
        # Анализируем все данные
        all_data = [('secret', s) for s in self.secrets] + [('non_secret', s) for s in self.non_secrets]
        
        for data_type, string in tqdm(all_data, desc="Анализ качества данных"):
            # Пустые строки
            if not string:
                issues['empty_strings'].append((data_type, string))
                continue
            
            # Слишком короткие (возможно бессмысленные)
            if len(string) < 8:  # Увеличил минимальную длину для секретов
                issues['too_short'].append((data_type, string))
            
            # Слишком длинные (возможно, содержат лишние данные)
            if len(string) > 512:  # Разумный лимит для секретов
                issues['too_long'].append((data_type, string[:100] + '...'))
            
            # Только пробельные символы
            if string.isspace():
                issues['whitespace_only'].append((data_type, repr(string)))
            
            # Непечатаемые символы
            if any(ord(c) < 32 and c not in '\t\n\r' for c in string):
                issues['non_printable_chars'].append((data_type, repr(string)))
            
            # Возможные тестовые данные
            test_indicators = ['test', 'example', 'sample', 'demo', 'fake', 'dummy', 'placeholder', 'lorem', 'ipsum']
            if any(indicator in string.lower() for indicator in test_indicators):
                issues['potential_test_data'].append((data_type, string))
        
        quality_issues = {
            'issues_summary': {k: len(v) for k, v in issues.items()},
            'total_issues': sum(len(v) for v in issues.values()),
            'issues_examples': {k: v[:5] for k, v in issues.items()},
            'issues_full': issues
        }
        
        self.analysis_results['quality_issues'] = quality_issues
        return quality_issues
    
    def analyze_pattern_distribution(self) -> Dict:
        """Анализ распределения паттернов в данных"""
        print("Анализирую распределение паттернов...")
        
        patterns = {
            'contains_digits': 0,
            'contains_uppercase': 0,
            'contains_lowercase': 0,
            'contains_special_chars': 0,
            'contains_spaces': 0,
            'alphanumeric_only': 0,
            'starts_with_prefix': defaultdict(int),
            'common_lengths': defaultdict(int),
            'entropy_distribution': []
        }
        
        # Общие префиксы для API ключей и токенов
        common_prefixes = ['sk-', 'pk-', 'api_', 'token_', 'key_', 'secret_', 'auth_', 'bearer_']
        
        all_strings = self.secrets + self.non_secrets
        
        for string in tqdm(all_strings, desc="Анализ паттернов"):
            if not string:
                continue
                
            # Базовые характеристики
            if any(c.isdigit() for c in string):
                patterns['contains_digits'] += 1
            if any(c.isupper() for c in string):
                patterns['contains_uppercase'] += 1
            if any(c.islower() for c in string):
                patterns['contains_lowercase'] += 1
            if any(not c.isalnum() and not c.isspace() for c in string):
                patterns['contains_special_chars'] += 1
            if ' ' in string:
                patterns['contains_spaces'] += 1
            if string.isalnum():
                patterns['alphanumeric_only'] += 1
            
            # Префиксы
            for prefix in common_prefixes:
                if string.lower().startswith(prefix):
                    patterns['starts_with_prefix'][prefix] += 1
            
            # Длины
            patterns['common_lengths'][len(string)] += 1
            
            # Энтропия (простая оценка)
            entropy = self._calculate_entropy(string)
            patterns['entropy_distribution'].append(entropy)
        
        # Статистика по энтропии
        if patterns['entropy_distribution']:
            patterns['entropy_stats'] = {
                'mean': statistics.mean(patterns['entropy_distribution']),
                'median': statistics.median(patterns['entropy_distribution']),
                'std': statistics.stdev(patterns['entropy_distribution']) if len(patterns['entropy_distribution']) > 1 else 0
            }
        
        # Топ длин
        patterns['top_lengths'] = dict(Counter(patterns['common_lengths']).most_common(10))
        patterns['starts_with_prefix'] = dict(patterns['starts_with_prefix'])
        
        self.analysis_results['pattern_distribution'] = patterns
        return patterns
    
    def _calculate_entropy(self, string: str) -> float:
        """Вычисляет энтропию Шеннона для строки"""
        if not string:
            return 0.0
        
        char_counts = Counter(string)
        string_length = len(string)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def generate_recommendations(self) -> Dict:
        """Генерирует рекомендации по улучшению качества датасетов"""
        print("Генерирую рекомендации...")
        
        recommendations = {
            'critical_issues': [],
            'warnings': [],
            'suggestions': [],
            'overall_quality_score': 0.0,
            'quality_score_10': 0.0,  # Оценка по 10-бальной шкале
            'fixable_issues': {}  # Проблемы, которые можно исправить автоматически
        }
        
        # Анализируем результаты
        stats = self.analysis_results.get('basic_statistics', {})
        duplicates = self.analysis_results.get('duplicates', {})
        coverage = self.analysis_results.get('rule_coverage', {})
        quality = self.analysis_results.get('quality_issues', {})
        
        # Система оценки (каждый критерий из 10 баллов)
        scores = {
            'dataset_size': 0,      # Размер датасета
            'class_balance': 0,     # Баланс классов
            'duplicates': 0,        # Отсутствие дубликатов
            'cross_class': 0,       # Отсутствие пересечений
            'rule_coverage': 0,     # Покрытие правилами
            'data_quality': 0       # Качество данных
        }
        
        # 1. Оценка размера датасета (0-10)
        total_count = stats.get('total_count', 0)
        if total_count >= 50000:
            scores['dataset_size'] = 10
        elif total_count >= 20000:
            scores['dataset_size'] = 8
        elif total_count >= 10000:
            scores['dataset_size'] = 6
        elif total_count >= 5000:
            scores['dataset_size'] = 4
        elif total_count >= 1000:
            scores['dataset_size'] = 2
        else:
            scores['dataset_size'] = 0
        
        # 2. Оценка баланса классов (0-10)
        balance = stats.get('class_balance', 0.5)
        if 0.4 <= balance <= 0.6:  # Идеальный баланс
            scores['class_balance'] = 10
        elif 0.3 <= balance <= 0.7:  # Хороший баланс
            scores['class_balance'] = 8
        elif 0.2 <= balance <= 0.8:  # Приемлемый баланс
            scores['class_balance'] = 6
        elif 0.1 <= balance <= 0.9:  # Плохой баланс
            scores['class_balance'] = 3
        else:  # Критически плохой баланс
            scores['class_balance'] = 0
        
        # 3. Оценка дубликатов (0-10)
        max_dup_ratio = max(duplicates.get('secrets_duplicate_ratio', 0), 
                           duplicates.get('non_secrets_duplicate_ratio', 0))
        if max_dup_ratio <= 0.01:  # ≤1% дубликатов
            scores['duplicates'] = 10
        elif max_dup_ratio <= 0.05:  # ≤5% дубликатов
            scores['duplicates'] = 7
        elif max_dup_ratio <= 0.1:   # ≤10% дубликатов
            scores['duplicates'] = 4
        elif max_dup_ratio <= 0.2:   # ≤20% дубликатов
            scores['duplicates'] = 2
        else:  # >20% дубликатов
            scores['duplicates'] = 0
        
        # 4. Оценка пересечений между классами (0-10)
        cross_class_count = duplicates.get('cross_class_duplicates', 0)
        if cross_class_count == 0:
            scores['cross_class'] = 10
        elif cross_class_count <= total_count * 0.001:  # ≤0.1% от общего количества
            scores['cross_class'] = 5
        else:  # >0.1% пересечений - критическая ошибка
            scores['cross_class'] = 0
        
        # 5. Оценка покрытия правилами (0-10)
        secrets_coverage = coverage.get('secrets_coverage_ratio', 0)
        if secrets_coverage >= 0.95:  # ≥95% покрытие
            scores['rule_coverage'] = 10
        elif secrets_coverage >= 0.9:   # ≥90% покрытие
            scores['rule_coverage'] = 8
        elif secrets_coverage >= 0.8:   # ≥80% покрытие
            scores['rule_coverage'] = 6
        elif secrets_coverage >= 0.7:   # ≥70% покрытие
            scores['rule_coverage'] = 4
        elif secrets_coverage >= 0.5:   # ≥50% покрытие
            scores['rule_coverage'] = 2
        else:  # <50% покрытие
            scores['rule_coverage'] = 0
        
        # 6. Оценка качества данных (0-10)
        issues_ratio = quality.get('total_issues', 0) / max(total_count, 1)
        if issues_ratio <= 0.01:  # ≤1% проблемных записей
            scores['data_quality'] = 10
        elif issues_ratio <= 0.05:  # ≤5% проблемных записей
            scores['data_quality'] = 7
        elif issues_ratio <= 0.1:   # ≤10% проблемных записей
            scores['data_quality'] = 4
        elif issues_ratio <= 0.2:   # ≤20% проблемных записей
            scores['data_quality'] = 2
        else:  # >20% проблемных записей
            scores['data_quality'] = 0
        
        # Итоговая оценка по 10-бальной шкале (средневзвешенная)
        weights = {
            'dataset_size': 0.15,
            'class_balance': 0.15,
            'duplicates': 0.15,
            'cross_class': 0.25,  # Самый важный критерий
            'rule_coverage': 0.20,
            'data_quality': 0.10
        }
        
        weighted_score = sum(scores[criterion] * weights[criterion] for criterion in scores)
        recommendations['quality_score_10'] = round(weighted_score, 1)
        
        # Старая 100-бальная система для совместимости
        score = weighted_score * 10  # Конвертируем в 100-бальную
        
        # Критические проблемы
        if total_count < 1000:
            recommendations['critical_issues'].append(
                f"Датасет слишком мал ({total_count:,} образцов). Рекомендуется минимум 10,000+ образцов для каждого класса."
            )
            score -= 20
        
        if cross_class_count > 0:
            recommendations['critical_issues'].append(
                f"Найдено {cross_class_count:,} одинаковых строк в обоих классах. "
                "Это критическая ошибка разметки!"
            )
            recommendations['fixable_issues']['cross_class_duplicates'] = True
            score -= 25
        
        if secrets_coverage < 0.7:
            recommendations['critical_issues'].append(
                f"Низкое покрытие секретов правилами ({secrets_coverage:.1%}). "
                "Многие секреты не детектируются существующими правилами."
            )
            score -= 20
        
        # Предупреждения
        if balance < 0.3 or balance > 0.7:
            recommendations['warnings'].append(
                f"Несбалансированные классы ({balance:.1%} секретов). "
                "Рекомендуется соотношение 30-70% для лучшего обучения."
            )
            score -= 10
        
        if max_dup_ratio > 0.05:
            recommendations['warnings'].append(
                f"Высокий процент дубликатов ({max_dup_ratio:.1%}). "
                "Дубликаты могут привести к переобучению."
            )
            recommendations['fixable_issues']['duplicates'] = True
            score -= 10
        
        if issues_ratio > 0.05:
            recommendations['warnings'].append(
                f"Много проблем качества данных ({quality.get('total_issues', 0):,} проблем). "
                "Требуется очистка данных."
            )
            recommendations['fixable_issues']['quality_issues'] = True
            score -= 15
        
        # Предложения по улучшению
        if total_count < 10000:
            recommendations['suggestions'].append(
                "Увеличьте размер датасета для лучшей генерализации модели."
            )
        
        if coverage.get('uncovered_secrets_count', 0) > 0:
            recommendations['suggestions'].append(
                f"Добавьте правила для {coverage.get('uncovered_secrets_count', 0):,} "
                "необнаруженных секретов или проверьте правильность их разметки."
            )
        
        recommendations['overall_quality_score'] = max(0, score)
        recommendations['detailed_scores'] = scores
        self.analysis_results['recommendations'] = recommendations
        
        return recommendations
    
    def create_backups(self):
        """Создает резервные копии датасетов"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        backup_dir = f"backup_{timestamp}"
        os.makedirs(backup_dir, exist_ok=True)
        
        secrets_backup = os.path.join(backup_dir, "Dataset_Secrets_backup.txt")
        non_secrets_backup = os.path.join(backup_dir, "Dataset_NonSecrets_backup.txt")
        
        shutil.copy2(self.secrets_path, secrets_backup)
        shutil.copy2(self.non_secrets_path, non_secrets_backup)
        
        print(f"Созданы резервные копии в папке: {backup_dir}")
        return backup_dir
    
    def fix_datasets(self):
        """Автоматически исправляет обнаруженные проблемы в датасетах"""
        print("\n" + "="*60)
        print("АВТОМАТИЧЕСКОЕ ИСПРАВЛЕНИЕ ДАТАСЕТОВ")
        print("="*60)
        
        if not self.analysis_results:
            print("Сначала необходимо провести анализ!")
            return
        
        # Создаем резервные копии
        backup_dir = self.create_backups()
        
        fixed_secrets = self.secrets.copy()
        fixed_non_secrets = self.non_secrets.copy()
        
        fixes_applied = []
        
        # 1. Удаляем пересечения между классами (критическая ошибка)
        duplicates = self.analysis_results.get('duplicates', {})
        cross_class = duplicates.get('cross_class_list', [])
        if cross_class:
            print(f"Удаляю {len(cross_class)} пересечений между классами...")
            # Удаляем из не-секретов, так как секреты важнее
            fixed_non_secrets = [s for s in fixed_non_secrets if s not in cross_class]
            fixes_applied.append(f"Удалены {len(cross_class)} пересечений между классами")
        
        # 2. Удаляем точные дубликаты
        secrets_dups = duplicates.get('secrets_duplicates_dict', {})
        non_secrets_dups = duplicates.get('non_secrets_duplicates_dict', {})
        
        if secrets_dups:
            print("Удаляю дубликаты из секретов...")
            fixed_secrets = list(set(fixed_secrets))  # Простое удаление дубликатов
            fixes_applied.append(f"Удалены дубликаты секретов")
        
        if non_secrets_dups:
            print("Удаляю дубликаты из не-секретов...")
            fixed_non_secrets = list(set(fixed_non_secrets))
            fixes_applied.append(f"Удалены дубликаты не-секретов")
        
        # 3. Удаляем проблемные строки
        quality_issues = self.analysis_results.get('quality_issues', {}).get('issues_full', {})
        
        # Собираем все проблемные строки для удаления
        problematic_strings = set()
        
        for issue_type, issues in quality_issues.items():
            if issue_type in ['empty_strings', 'too_short', 'too_long', 'whitespace_only', 
                             'non_printable_chars', 'potential_test_data']:
                for data_type, string in issues:
                    if issue_type == 'too_long':
                        # Для слишком длинных строк ищем оригинальную строку
                        original_string = string.replace('...', '')
                        for s in (fixed_secrets + fixed_non_secrets):
                            if s.startswith(original_string):
                                problematic_strings.add(s)
                                break
                    else:
                        problematic_strings.add(string)
        
        if problematic_strings:
            print(f"Удаляю {len(problematic_strings)} проблемных строк...")
            fixed_secrets = [s for s in fixed_secrets if s not in problematic_strings]
            fixed_non_secrets = [s for s in fixed_non_secrets if s not in problematic_strings]
            fixes_applied.append(f"Удалены {len(problematic_strings)} проблемных строк")
        
        # 4. Удаляем необнаруженные секреты (возможно, это ложные срабатывания)
        coverage = self.analysis_results.get('rule_coverage', {})
        uncovered_secrets = coverage.get('uncovered_secrets_list', [])
        
        if uncovered_secrets and len(uncovered_secrets) < len(fixed_secrets) * 0.3:  # Не более 30%
            print(f"Удаляю {len(uncovered_secrets)} необнаруженных 'секретов' (возможно, ложные срабатывания)...")
            fixed_secrets = [s for s in fixed_secrets if s not in uncovered_secrets]
            fixes_applied.append(f"Удалены {len(uncovered_secrets)} необнаруженных секретов")
        
        # 5. Балансировка классов (опционально)
        secrets_count = len(fixed_secrets)
        non_secrets_count = len(fixed_non_secrets)
        
        if secrets_count > 0 and non_secrets_count > 0:
            balance = secrets_count / (secrets_count + non_secrets_count)
            if balance < 0.2:  # Слишком мало секретов
                # Урезаем не-секреты
                target_non_secrets = min(non_secrets_count, secrets_count * 4)  # Соотношение 1:4
                fixed_non_secrets = fixed_non_secrets[:target_non_secrets]
                fixes_applied.append(f"Урезаны не-секреты для баланса (осталось {target_non_secrets})")
            elif balance > 0.8:  # Слишком много секретов
                # Урезаем секреты
                target_secrets = min(secrets_count, non_secrets_count * 4)  # Соотношение 4:1
                fixed_secrets = fixed_secrets[:target_secrets]
                fixes_applied.append(f"Урезаны секреты для баланса (осталось {target_secrets})")
        
        # Сохраняем исправленные датасеты
        print("Сохраняю исправленные датасеты...")
        
        with open(self.secrets_path, 'w', encoding='utf-8') as f:
            for secret in tqdm(fixed_secrets, desc="Сохраняю секреты"):
                f.write(secret + '\n')
        
        with open(self.non_secrets_path, 'w', encoding='utf-8') as f:
            for non_secret in tqdm(fixed_non_secrets, desc="Сохраняю не-секреты"):
                f.write(non_secret + '\n')
        
        # Обновляем данные в анализаторе
        self.secrets = fixed_secrets
        self.non_secrets = fixed_non_secrets
        
        # Выводим отчет об исправлениях
        print("\n" + "="*60)
        print("ОТЧЕТ ОБ ИСПРАВЛЕНИЯХ")
        print("="*60)
        
        original_total = self.analysis_results['basic_statistics']['total_count']
        new_total = len(fixed_secrets) + len(fixed_non_secrets)
        
        print(f"Исходный размер датасетов: {original_total}")
        print(f"Новый размер датасетов: {new_total}")
        print(f"Удалено записей: {original_total - new_total}")
        print(f"Новый баланс классов: {len(fixed_secrets)}/{len(fixed_non_secrets)} " +
              f"({len(fixed_secrets)/(len(fixed_secrets) + len(fixed_non_secrets)):.1%} секретов)")
        print(f"Резервные копии сохранены в: {backup_dir}")
        
        print("\nПрименённые исправления:")
        for fix in fixes_applied:
            print(f"  ✓ {fix}")
        
        print(f"\nДатасеты обновлены:")
        print(f"  - {self.secrets_path}")
        print(f"  - {self.non_secrets_path}")
    
    def generate_report(self) -> str:
        """Генерирует полный отчет об анализе качества"""
        # Выполняем все анализы
        self.analyze_basic_statistics()
        self.analyze_duplicates()
        self.analyze_rule_coverage()
        self.analyze_data_quality_issues()
        self.analyze_pattern_distribution()
        recommendations = self.generate_recommendations()
        
        report = []
        report.append("=" * 80)
        report.append("ОТЧЕТ О КАЧЕСТВЕ ДАТАСЕТОВ ДЛЯ ДЕТЕКЦИИ СЕКРЕТОВ")
        report.append("=" * 80)
        report.append("")
        
        report.append(f"ОБЩАЯ ОЦЕНКА КАЧЕСТВА: {recommendations['quality_score_10']:.1f}/10")
        
        # Детализация оценки
        detailed_scores = recommendations.get('detailed_scores', {})
        score_labels = {
            'dataset_size': 'Размер датасета',
            'class_balance': 'Баланс классов', 
            'duplicates': 'Отсутствие дубликатов',
            'cross_class': 'Отсутствие пересечений',
            'rule_coverage': 'Покрытие правилами',
            'data_quality': 'Качество данных'
        }
        
        report.append("\nДетализация оценки:")
        for criterion, score in detailed_scores.items():
            label = score_labels.get(criterion, criterion)
            report.append(f"  {label}: {score:.1f}/10")
        
        # Качественная оценка
        score_10 = recommendations['quality_score_10']
        if score_10 >= 8.5:
            quality_label = "ОТЛИЧНО"
        elif score_10 >= 7.0:
            quality_label = "ХОРОШО"
        elif score_10 >= 5.5:
            quality_label = "УДОВЛЕТВОРИТЕЛЬНО"
        elif score_10 >= 3.0:
            quality_label = "ПЛОХО"
        else:
            quality_label = "КРИТИЧНО"
        
        report.append(f"\nКачественная оценка: {quality_label}")
        report.append("")
        
        # Базовая статистика
        stats = self.analysis_results['basic_statistics']
        report.append("1. БАЗОВАЯ СТАТИСТИКА")
        report.append("-" * 20)
        report.append(f"Общее количество образцов: {stats['total_count']:,}")
        report.append(f"Секреты: {stats['secrets_count']:,}")
        report.append(f"Не-секреты: {stats['non_secrets_count']:,}")
        report.append(f"Баланс классов: {stats['class_balance']:.1%} секретов")
        report.append(f"Средняя длина секретов: {stats['secrets_avg_length']:.1f} ± {stats['secrets_length_std']:.1f}")
        report.append(f"Средняя длина не-секретов: {stats['non_secrets_avg_length']:.1f} ± {stats['non_secrets_length_std']:.1f}")
        report.append("")
        
        # Дубликаты
        duplicates = self.analysis_results['duplicates']
        report.append("2. АНАЛИЗ ДУБЛИКАТОВ")
        report.append("-" * 18)
        report.append(f"Точные дубликаты в секретах: {duplicates['secrets_exact_duplicates']:,}")
        report.append(f"Точные дубликаты в не-секретах: {duplicates['non_secrets_exact_duplicates']:,}")
        report.append(f"Пересечения между классами: {duplicates['cross_class_duplicates']:,} ⚠️")
        
        if duplicates['duplicate_examples']['cross_class']:
            report.append("\nПримеры пересечений между классами:")
            for example in duplicates['duplicate_examples']['cross_class']:
                report.append(f"  • {example}")
        report.append("")
        
        # Покрытие правилами
        coverage = self.analysis_results['rule_coverage']
        report.append("3. ПОКРЫТИЕ ПРАВИЛАМИ")
        report.append("-" * 19)
        report.append(f"Всего правил: {coverage['total_rules']}")
        report.append(f"Покрытие секретов: {coverage['secrets_coverage_ratio']:.1%}")
        report.append(f"Покрытие не-секретов: {coverage['non_secrets_coverage_ratio']:.1%}")
        report.append(f"Необнаруженные секреты: {coverage['uncovered_secrets_count']:,}")
        report.append(f"Необнаруженные не-секреты: {coverage['uncovered_non_secrets_count']:,}")
        
        if coverage['uncovered_examples']['secrets']:
            report.append("\nПримеры необнаруженных секретов:")
            for example in coverage['uncovered_examples']['secrets']:
                report.append(f"  • {example}")
        report.append("")
        
        # Проблемы качества
        quality = self.analysis_results['quality_issues']
        report.append("4. ПРОБЛЕМЫ КАЧЕСТВА ДАННЫХ")
        report.append("-" * 27)
        report.append(f"Всего проблем: {quality['total_issues']:,}")
        for issue_type, count in quality['issues_summary'].items():
            if count > 0:
                issue_name = {
                    'empty_strings': 'Пустые строки',
                    'too_short': 'Слишком короткие',
                    'too_long': 'Слишком длинные',
                    'non_printable_chars': 'Непечатаемые символы',
                    'encoding_issues': 'Проблемы кодировки',
                    'whitespace_only': 'Только пробелы',
                    'potential_test_data': 'Возможные тестовые данные'
                }.get(issue_type, issue_type)
                report.append(f"  {issue_name}: {count:,}")
        report.append("")
        
        # Рекомендации
        report.append("5. РЕКОМЕНДАЦИИ")
        report.append("-" * 14)
        
        if recommendations['critical_issues']:
            report.append("🔴 КРИТИЧЕСКИЕ ПРОБЛЕМЫ:")
            for issue in recommendations['critical_issues']:
                report.append(f"  • {issue}")
            report.append("")
        
        if recommendations['warnings']:
            report.append("🟡 ПРЕДУПРЕЖДЕНИЯ:")
            for warning in recommendations['warnings']:
                report.append(f"  • {warning}")
            report.append("")
        
        if recommendations['suggestions']:
            report.append("💡 ПРЕДЛОЖЕНИЯ ПО УЛУЧШЕНИЮ:")
            for suggestion in recommendations['suggestions']:
                report.append(f"  • {suggestion}")
            report.append("")
        
        # Автоматически исправимые проблемы
        fixable = recommendations.get('fixable_issues', {})
        if fixable:
            report.append("🔧 АВТОМАТИЧЕСКИ ИСПРАВИМЫЕ ПРОБЛЕМЫ:")
            if fixable.get('cross_class_duplicates'):
                report.append("  • Пересечения между классами можно удалить")
            if fixable.get('duplicates'):
                report.append("  • Дубликаты можно удалить")
            if fixable.get('quality_issues'):
                report.append("  • Проблемные строки можно очистить")
            report.append("")
        
        # Заключение
        report.append("=" * 80)
        report.append("ЗАКЛЮЧЕНИЕ")
        report.append("=" * 80)
        
        score_10 = recommendations['quality_score_10']
        if score_10 >= 8.5:
            report.append("Датасеты имеют отличное качество и полностью готовы для обучения модели.")
        elif score_10 >= 7.0:
            report.append("Датасеты имеют хорошее качество с незначительными недостатками.")
        elif score_10 >= 5.5:
            report.append("Датасеты имеют удовлетворительное качество, рекомендуются улучшения.")
        elif score_10 >= 3.0:
            report.append("Датасеты имеют плохое качество и требуют серьезных исправлений.")
        else:
            report.append("Датасеты имеют критически низкое качество и требуют полной переработки.")
        
        report.append("")
        report.append("Оценка основана на 6 ключевых критериях:")
        report.append("• Размер датасета (15% веса)")
        report.append("• Баланс классов (15% веса)")  
        report.append("• Отсутствие дубликатов (15% веса)")
        report.append("• Отсутствие пересечений между классами (25% веса) - критично!")
        report.append("• Покрытие правилами (20% веса)")
        report.append("• Качество данных (10% веса)")
        report.append("")
        report.append("Рекомендации основаны на лучших практиках машинного обучения")
        report.append("и специфике задач детекции секретов в исходном коде.")
        
        return "\n".join(report)
    
    def save_analysis_json(self, filepath: str):
        """Сохраняет результаты анализа в JSON файл"""
        # Убираем большие списки из JSON для экономии места
        analysis_copy = self.analysis_results.copy()
        
        # Ограничиваем размер сохраняемых списков
        if 'duplicates' in analysis_copy:
            analysis_copy['duplicates'].pop('secrets_duplicates_dict', None)
            analysis_copy['duplicates'].pop('non_secrets_duplicates_dict', None)
            analysis_copy['duplicates'].pop('cross_class_list', None)
        
        if 'rule_coverage' in analysis_copy:
            analysis_copy['rule_coverage'].pop('uncovered_secrets_list', None)
            analysis_copy['rule_coverage'].pop('uncovered_non_secrets_list', None)
        
        if 'quality_issues' in analysis_copy:
            analysis_copy['quality_issues'].pop('issues_full', None)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis_copy, f, ensure_ascii=False, indent=2)


def main():
    """Основная функция для запуска анализа"""
    # Пути к файлам (настройте под ваши пути)
    rules_path = "../Settings/rules.yml"
    secrets_path = "../Datasets/Dataset_Secrets.txt"
    non_secrets_path = "../Datasets/Dataset_NonSecrets.txt"
    
    print("Запуск анализа качества датасетов для детекции секретов...")
    print("=" * 60)
    
    # Проверяем существование файлов
    missing_files = []
    for path, name in [(rules_path, "rules.yml"), 
                       (secrets_path, "Dataset_Secrets.txt"), 
                       (non_secrets_path, "Dataset_NonSecrets.txt")]:
        if not os.path.exists(path):
            missing_files.append((path, name))
    
    if missing_files:
        print("ОШИБКА: Не найдены следующие файлы:")
        for path, name in missing_files:
            print(f"  - {name}: {path}")
        print("\nПожалуйста, проверьте пути и создайте недостающие файлы.")
        return
    
    try:
        # Создаем анализатор
        analyzer = DatasetQualityAnalyzer(rules_path, secrets_path, non_secrets_path)
        
        # Генерируем отчет
        print("\nЗапускаю полный анализ...")
        report = analyzer.generate_report()
        
        # Выводим отчет
        print("\n" + report)
        
        # Сохраняем детальные результаты
        print("\nСохраняю результаты анализа...")
        analyzer.save_analysis_json("dataset_analysis_results.json")
        print("Детальные результаты сохранены в: dataset_analysis_results.json")
        
        # Сохраняем отчет в файл
        with open("dataset_quality_report.txt", "w", encoding="utf-8") as f:
            f.write(report)
        print("Отчет сохранен в: dataset_quality_report.txt")
        
        # Предлагаем исправить датасеты
        recommendations = analyzer.analysis_results.get('recommendations', {})
        fixable_issues = recommendations.get('fixable_issues', {})
        
        if fixable_issues:
            print("\n" + "="*60)
            print("НАЙДЕНЫ АВТОМАТИЧЕСКИ ИСПРАВИМЫЕ ПРОБЛЕМЫ!")
            print("="*60)
            
            if fixable_issues.get('cross_class_duplicates'):
                print("🔴 Критично: найдены пересечения между классами")
            if fixable_issues.get('duplicates'):
                print("⚠️  Найдены дубликаты")
            if fixable_issues.get('quality_issues'):
                print("⚠️  Найдены проблемы качества данных")
            
            print("\nЭти проблемы могут серьезно повлиять на качество обучения модели.")
            
            while True:
                choice = input("\nХотите автоматически исправить датасеты? (y/n): ").lower().strip()
                if choice in ['y', 'yes', 'да', 'д']:
                    analyzer.fix_datasets()
                    
                    # Предлагаем повторный анализ
                    reanalyze = input("\nХотите провести повторный анализ исправленных датасетов? (y/n): ").lower().strip()
                    if reanalyze in ['y', 'yes', 'да', 'д']:
                        print("\n" + "="*60)
                        print("ПОВТОРНЫЙ АНАЛИЗ ИСПРАВЛЕННЫХ ДАТАСЕТОВ")
                        print("="*60)
                        
                        # Очищаем предыдущие результаты
                        analyzer.analysis_results = {}
                        
                        # Проводим новый анализ
                        new_report = analyzer.generate_report()
                        print("\n" + new_report)
                        
                        # Сохраняем новые результаты
                        analyzer.save_analysis_json("dataset_analysis_results_fixed.json")
                        with open("dataset_quality_report_fixed.txt", "w", encoding="utf-8") as f:
                            f.write(new_report)
                        
                        print("\nОбновленные результаты сохранены:")
                        print("- dataset_analysis_results_fixed.json")
                        print("- dataset_quality_report_fixed.txt")
                    
                    break
                elif choice in ['n', 'no', 'нет', 'н']:
                    print("Датасеты не изменены. Рекомендуется исправить проблемы вручную.")
                    break
                else:
                    print("Пожалуйста, введите 'y' (да) или 'n' (нет)")
        else:
            print("\n✅ Автоматически исправимых проблем не найдено.")
        
        print(f"\n🎉 Анализ завершен! Проверьте файлы с результатами.")
        
    except KeyboardInterrupt:
        print("\n\nАнализ прерван пользователем.")
    except Exception as e:
        print(f"\nОшибка при анализе: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()