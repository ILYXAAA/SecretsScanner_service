import logging
import math
import os
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from app.repo_utils import recover_zip_path_encoding

logger = logging.getLogger("forbidden_check")

DEFAULT_CONFIG_PATH = "Settings/languages_repo_config.yml"


def _normalize_extension(ext: str) -> str:
    ext = ext.strip().lower()
    if not ext:
        return ext
    return ext if ext.startswith(".") else f".{ext}"


def normalize_languages_repo_config(config: dict) -> dict:
    """
    Поддерживает два формата forbidden_languages:
    - список имён: [pas, perl] — языки берутся из language_extensions
    - словарь язык → расширения: {1C: [.bsl, .os], Abap: [.abap]}
    """
    normalized = dict(config)
    language_extensions = {
        lang: [_normalize_extension(e) for e in exts if isinstance(e, str)]
        for lang, exts in (normalized.get("language_extensions") or {}).items()
        if isinstance(exts, list)
    }

    forbidden = normalized.get("forbidden_languages", [])
    forbidden_set: set[str] = set()

    if isinstance(forbidden, dict):
        for lang, exts in forbidden.items():
            lang_key = str(lang)
            forbidden_set.add(lang_key)
            if not isinstance(exts, list):
                continue
            from_forbidden = [_normalize_extension(e) for e in exts if isinstance(e, str) and e.strip()]
            existing = language_extensions.get(lang_key, [])
            language_extensions[lang_key] = list(dict.fromkeys(existing + from_forbidden))
    elif isinstance(forbidden, list):
        forbidden_set = {str(x) for x in forbidden if x is not None}
    else:
        forbidden_set = set()

    normalized["language_extensions"] = language_extensions
    normalized["_forbidden_language_set"] = forbidden_set
    return normalized


def load_languages_repo_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError("languages_repo_config.yml должен содержать YAML-объект")
    return normalize_languages_repo_config(raw)


class ForbiddenRepositoryAnalyzer:
    def __init__(self, config: dict, project_name: str = "unknown"):
        self.config = config
        self.project_name = project_name
        self.violations = []
        self.languages = defaultdict(int)
        self.categories = defaultdict(int)
        self.extensions_found = defaultdict(int)
        self.blocking_extensions = defaultdict(int)
        self.non_blocking_extensions = defaultdict(int)
        self.total_size = 0
        self.total_files = 0
        self.scan_date = datetime.now().isoformat()
        self._forbidden_languages_found = set()
        self.skipped_dotfiles = 0
        self.skipped_oversized = 0
        self.skipped_os_errors = 0

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def has_null_bytes(self, file_path: str, check_bytes: int = 1024) -> bool:
        try:
            with open(file_path, "rb") as f:
                return b"\x00" in f.read(check_bytes)
        except OSError:
            return False

    def get_mime_encoding(self, file_path: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["file", "--mime-encoding", str(file_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.split(":")[-1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def is_binary_file(self, file_path: str) -> tuple[bool, str]:
        ext = Path(file_path).suffix.lower()

        if ext in self.config.get("non_blocking_static_extensions", []):
            return True, "static_non_blocking"

        if ext in self.config["binary_extensions"]:
            return True, "binary_extension"

        try:
            mime_encoding = self.get_mime_encoding(file_path)
            if mime_encoding and mime_encoding == "binary":
                return True, "mime_binary"

            if self.has_null_bytes(file_path):
                return True, "null_bytes"

            with open(file_path, "rb") as f:
                data = f.read(8192)
                entropy = self.calculate_entropy(data)
                if entropy > self.config["entropy_threshold"]:
                    return True, f"high_entropy_{entropy:.2f}"

            return False, "text"
        except OSError as e:
            return False, f"error_{e}"

    def detect_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        for lang, extensions in self.config["language_extensions"].items():
            if ext in extensions:
                return lang
        return "unknown"

    def categorize_file(self, file_path: str) -> str:
        filename = os.path.basename(file_path)
        ext = Path(file_path).suffix.lower()

        if ext in self.config.get("non_blocking_static_extensions", []):
            return "static"

        if ext in self.config["archive_extensions"]:
            return "archive"

        if ext in self.config["config_extensions"] or filename in self.config["config_filenames"]:
            return "config"

        is_binary, _ = self.is_binary_file(file_path)
        if is_binary:
            return "binary"

        if self.detect_language(file_path) != "unknown":
            return "code"

        return "other"

    def _is_forbidden_extension(self, ext: str) -> bool:
        if not ext:
            return False
        if ext in self.config.get("non_blocking_static_extensions", []):
            return False
        forbidden_exts = set(self.config["binary_extensions"]) | set(self.config["archive_extensions"])
        return ext in forbidden_exts

    def _collect_violation_reasons(
        self,
        ext: str,
        category: str,
        language: str,
        is_binary: bool,
        binary_reason: str,
    ) -> list[str]:
        reasons = []

        if language in self.config.get("_forbidden_language_set", set()) and category != "static":
            reasons.append(f"forbidden_language: {language}")

        if self._is_forbidden_extension(ext):
            reasons.append(f"forbidden_extension: {ext}")

        if is_binary and binary_reason not in ("static_non_blocking",) and binary_reason.startswith("high_entropy"):
            reasons.append("high_entropy")

        return reasons

    def analyze_file(self, file_path: str, relative_path: str) -> None:
        try:
            file_size = os.path.getsize(file_path)
            max_size = self.config["max_file_size_mb"] * 1024 * 1024
            if file_size > max_size:
                return

            ext = Path(file_path).suffix.lower()
            category = self.categorize_file(file_path)
            language = self.detect_language(file_path)
            is_binary, binary_reason = self.is_binary_file(file_path)
            is_blocking = binary_reason != "static_non_blocking"

            self.total_files += 1
            self.total_size += file_size
            self.categories[category] += 1

            if language != "unknown":
                self.languages[language] += 1

            if ext:
                self.extensions_found[ext] += 1
                if ext in self.config.get("non_blocking_static_extensions", []):
                    self.non_blocking_extensions[ext] += 1
                elif is_binary and binary_reason != "static_non_blocking":
                    self.blocking_extensions[ext] += 1

            violation_reasons = self._collect_violation_reasons(
                ext, category, language, is_binary, binary_reason
            )
            if not violation_reasons:
                return

            for reason in violation_reasons:
                if reason.startswith("forbidden_language:"):
                    self._forbidden_languages_found.add(language)

            self.violations.append({
                "path": relative_path,
                "size": file_size,
                "category": category,
                "language": language,
                "extension": ext,
                "is_binary": is_binary,
                "binary_reason": binary_reason,
                "is_blocking": is_blocking,
                "violation_reasons": violation_reasons,
            })
        except OSError:
            self.skipped_os_errors += 1
            return

    def _collect_files(self, directory: str) -> list[tuple[str, str]]:
        """Собирает список файлов для анализа (аналогично scanner.py)."""
        file_list = []
        max_size = self.config["max_file_size_mb"] * 1024 * 1024

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]

            for filename in files:
                if filename.startswith("."):
                    self.skipped_dotfiles += 1
                    continue

                file_path = os.path.join(root, filename)
                try:
                    if os.path.getsize(file_path) > max_size:
                        self.skipped_oversized += 1
                        continue
                except OSError:
                    self.skipped_os_errors += 1
                    continue

                relative_path = recover_zip_path_encoding(os.path.relpath(file_path, directory))
                file_list.append((file_path, relative_path))

        return file_list

    def scan_directory(self, directory: str) -> None:
        collection_start = time.time()
        file_list = self._collect_files(directory)
        collection_time = time.time() - collection_start

        logger.info(
            f"['{self.project_name}'] Найдено файлов для проверки: '{len(file_list)}' "
            f"(время сбора: {collection_time:.2f}с)"
        )

        skipped_parts = []
        if self.skipped_dotfiles:
            skipped_parts.append(f"dotfiles=`{self.skipped_dotfiles}`")
        if self.skipped_oversized:
            skipped_parts.append(f"oversized=`{self.skipped_oversized}`")
        if self.skipped_os_errors:
            skipped_parts.append(f"os_errors=`{self.skipped_os_errors}`")
        if skipped_parts:
            logger.info(f"['{self.project_name}'] Пропущены файлы: {', '.join(skipped_parts)}")

        analysis_start = time.time()
        for file_path, relative_path in file_list:
            self.analyze_file(file_path, relative_path)
        analysis_time = time.time() - analysis_start

        logger.info(f"['{self.project_name}'] Анализ файлов завершён (время: {analysis_time:.2f}с)")

    def build_result(self) -> dict:
        violations_count = len(self.violations)
        return {
            "violations": self.violations,
            "languages": dict(self.languages),
            "categories": dict(self.categories),
            "extensions_found": dict(self.extensions_found),
            "blocking_extensions": dict(self.blocking_extensions),
            "non_blocking_extensions": dict(self.non_blocking_extensions),
            "total_size": self.total_size,
            "scan_date": self.scan_date,
            "summary": {
                "total_files": self.total_files,
                "violations_count": violations_count,
                "forbidden_languages_found": sorted(self._forbidden_languages_found),
                "blocking_extensions_count": len(self.blocking_extensions),
                "passed": violations_count == 0,
            },
        }


def analyze_repository(
    repo_path: str,
    config_path: str = DEFAULT_CONFIG_PATH,
    project_name: str = "unknown",
) -> dict:
    scan_start = time.time()
    logger.info(f"['{project_name}'] Начинаю forbidden check, repo_path='{repo_path}'")

    config = load_languages_repo_config(config_path)
    analyzer = ForbiddenRepositoryAnalyzer(config, project_name=project_name)

    if os.path.isdir(repo_path):
        analyzer.scan_directory(repo_path)
    else:
        logger.warning(f"['{project_name}'] Путь не является директорией: '{repo_path}'")

    result = analyzer.build_result()
    summary = result["summary"]
    total_time = time.time() - scan_start

    top_languages = sorted(analyzer.languages.items(), key=lambda x: x[1], reverse=True)[:10]
    languages_str = ", ".join(f"{lang}={count}" for lang, count in top_languages) or "нет"
    top_categories = ", ".join(f"{cat}={count}" for cat, count in sorted(analyzer.categories.items())) or "нет"
    blocking_exts = ", ".join(f"`{ext}`" for ext in sorted(analyzer.blocking_extensions.keys())[:15]) or "нет"

    logger.info(f"['{project_name}'] Категории файлов: {top_categories}")
    logger.info(f"['{project_name}'] Языки (top-10): {languages_str}")
    if summary["violations_count"]:
        logger.info(
            f"['{project_name}'] Блокирующие расширения: {blocking_exts}"
        )
        logger.info(
            f"['{project_name}'] Запрещённые языки: "
            f"{', '.join(summary['forbidden_languages_found']) or 'нет'}"
        )

    logger.info(
        f"['{project_name}'] Forbidden check завершён. "
        f"Файлов: '{summary['total_files']}', нарушений: '{summary['violations_count']}', "
        f"passed: '{summary['passed']}' (общее время: {total_time:.2f}с)"
    )

    return result
