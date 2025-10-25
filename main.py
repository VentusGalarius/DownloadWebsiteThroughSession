import json
import re
import requests
import os
import time
import base64
import hashlib
import hmac
import logging
import sys
from typing import Dict, Optional, Set, List, Any, Tuple
from urllib.parse import urlparse, parse_qs, quote, urljoin, urlencode
from base64 import b64encode, b64decode
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import random
import string
import threading
from queue import Queue, Empty
from pathlib import Path
import urllib3
from cryptography.fernet import Fernet
import pickle
import uuid
from enum import Enum
import inspect
from dataclasses import dataclass
from contextlib import contextmanager

# =============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# =============================================================================

class FragmentConstants:
    """Константы для работы с Fragment.com"""
    
    # Базовые URL
    OAUTH_URL = "https://oauth.telegram.org"
    FRAGMENT_URL = "https://fragment.com"
    FRAGMENT_API_URL = "https://fragment.com/api"
    
    # Параметры OAuth
    BOT_ID = "5444323279"
    ORIGIN_URL = "https://fragment.com"
    RETURN_TO_URL = "https://fragment.com"
    REQUEST_ACCESS = "write"
    
    # User Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ]
    
    # Настройки запросов
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 5
    RETRY_DELAY_BASE = 2
    DEFAULT_DELAY = 1.5
    
    # Настройки скачивания
    MAX_DEPTH = 4
    CONCURRENT_WORKERS = 4
    CHUNK_SIZE = 8192
    
    # Исключаемые пути по умолчанию
    EXCLUDED_PATHS = {'username', 'number', 'phone', 'gift', 'logout'}
    
    # Директории
    BASE_OUTPUT_DIR = "./fragment_complete_site"
    SESSION_STORAGE_DIR = "./fragment_sessions"
    LOGS_DIR = "./fragment_logs"
    
    # Настройки логирования
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'


class AuthSteps(Enum):
    """Этапы процесса авторизации"""
    INITIALIZED = "initialized"
    PHONE_SENT = "phone_sent"
    CONFIRMED = "confirmed"
    LINK_OBTAINED = "link_obtained"
    CALLBACK_PROCESSED = "callback_processed"
    LOGIN_LINK_EXTRACTED = "login_link_extracted"
    FRAGMENT_AUTHENTICATED = "fragment_authenticated"
    WALLET_CONNECTED = "wallet_connected"
    COMPLETED = "completed"


class DownloadStatus(Enum):
    """Статусы скачивания"""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AuthState:
    """Состояние авторизации"""
    stel_ssid: Optional[str] = None
    stel_tsession: Optional[str] = None
    stel_token: Optional[str] = None
    auth_result: Optional[str] = None
    login_link: Optional[str] = None
    fragment_cookies: Dict[str, str] = None
    user_data: Dict[str, Any] = None
    wallet_connected: bool = False
    current_step: AuthSteps = AuthSteps.INITIALIZED
    session_id: Optional[str] = None
    
    def __post_init__(self):
        if self.fragment_cookies is None:
            self.fragment_cookies = {}
        if self.user_data is None:
            self.user_data = {}


@dataclass
class DownloadStats:
    """Статистика скачивания"""
    total_pages: int = 0
    downloaded_pages: int = 0
    total_assets: int = 0
    downloaded_assets: int = 0
    total_size_bytes: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def duration(self) -> Optional[timedelta]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def success_rate(self) -> float:
        total = self.downloaded_pages + self.downloaded_assets
        expected = self.total_pages + self.total_assets
        return (total / expected * 100) if expected > 0 else 0.0


# =============================================================================
# СИСТЕМА ЛОГГИРОВАНИЯ
# =============================================================================

class FragmentLogger:
    """Продвинутая система логирования для Fragment"""
    
    def __init__(self, name: str, log_level: int = FragmentConstants.LOG_LEVEL):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Создаем директорию для логов
        Path(FragmentConstants.LOGS_DIR).mkdir(exist_ok=True)
        
        # Форматтер с детальной информацией
        formatter = logging.Formatter(FragmentConstants.LOG_FORMAT)
        
        # File handler
        file_handler = logging.FileHandler(
            f"{FragmentConstants.LOGS_DIR}/fragment_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        
        # Очищаем существующие обработчики и добавляем новые
        self.logger.handlers.clear()
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Отключаем propagation для избежания дублирования
        self.logger.propagate = False
    
    def get_logger(self) -> logging.Logger:
        return self.logger
    
    @contextmanager
    def log_execution_time(self, operation: str):
        """Контекстный менеджер для логирования времени выполнения"""
        start_time = time.time()
        self.logger.info(f"Начало операции: {operation}")
        
        try:
            yield
        finally:
            execution_time = time.time() - start_time
            self.logger.info(f"Завершение операции: {operation} - Время выполнения: {execution_time:.2f} сек")


# =============================================================================
# ИСКЛЮЧЕНИЯ
# =============================================================================

class FragmentBaseError(Exception):
    """Базовое исключение для всех ошибок Fragment"""
    
    def __init__(self, message: str, error_code: str = None, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self):
        base_str = f"{self.__class__.__name__}: {self.message}"
        if self.error_code:
            base_str += f" (Код: {self.error_code})"
        return base_str


class TelegramAuthError(FragmentBaseError):
    """Ошибка авторизации Telegram"""
    
    def __init__(self, message: str, step: AuthSteps = None, response_data: Dict = None):
        super().__init__(message, "TELEGRAM_AUTH_ERROR", {
            "step": step.value if step else None,
            "response_data": response_data
        })
        self.step = step


class FragmentAPIError(FragmentBaseError):
    """Ошибка API Fragment"""
    
    def __init__(self, message: str, status_code: int = None, api_method: str = None):
        super().__init__(message, "FRAGMENT_API_ERROR", {
            "status_code": status_code,
            "api_method": api_method
        })
        self.status_code = status_code
        self.api_method = api_method


class NetworkError(FragmentBaseError):
    """Сетевая ошибка"""
    
    def __init__(self, message: str, url: str = None, original_exception: Exception = None):
        super().__init__(message, "NETWORK_ERROR", {
            "url": url,
            "original_exception": str(original_exception) if original_exception else None
        })
        self.url = url
        self.original_exception = original_exception


class SessionExpiredError(FragmentBaseError):
    """Ошибка истекшей сессии"""
    
    def __init__(self, message: str = "Сессия истекла", session_id: str = None):
        super().__init__(message, "SESSION_EXPIRED", {"session_id": session_id})
        self.session_id = session_id


class DownloadError(FragmentBaseError):
    """Ошибка скачивания"""
    
    def __init__(self, message: str, url: str = None, status_code: int = None):
        super().__init__(message, "DOWNLOAD_ERROR", {
            "url": url,
            "status_code": status_code
        })
        self.url = url
        self.status_code = status_code


# =============================================================================
# МЕНЕДЖЕР СЕССИЙ С ШИФРОВАНИЕМ
# =============================================================================

class SessionManager:
    """Продвинутый менеджер сессий с шифрованием и сжатием"""
    
    def __init__(self, storage_dir: str = FragmentConstants.SESSION_STORAGE_DIR):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.logger = FragmentLogger("SessionManager").get_logger()
        
        # Инициализация шифрования
        self._setup_encryption()
        
        self.logger.info(f"Менеджер сессий инициализирован, директория: {self.storage_dir}")
    
    def _setup_encryption(self):
        """Настройка системы шифрования"""
        try:
            key_file = self.storage_dir / "master.key"
            
            if not key_file.exists():
                # Генерируем новый ключ
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                self.logger.info("Сгенерирован новый мастер-ключ шифрования")
            else:
                # Загружаем существующий ключ
                with open(key_file, 'rb') as f:
                    key = f.read()
                self.logger.info("Загружен существующий мастер-ключ шифрования")
            
            self.fernet = Fernet(key)
            
        except Exception as e:
            self.logger.error(f"Ошибка настройки шифрования: {e}")
            raise FragmentBaseError(f"Не удалось настроить шифрование: {e}")
    
    def _generate_session_id(self, phone_number: str) -> str:
        """Генерация уникального ID сессии на основе номера телефона"""
        salt = str(uuid.uuid4())[:8]
        data = f"{phone_number}_{salt}_{datetime.now().timestamp()}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def save_session(self, auth_state: AuthState, phone_number: str) -> str:
        """Сохранение сессии с шифрованием"""
        session_id = self._generate_session_id(phone_number)
        
        try:
            session_data = {
                "session_id": session_id,
                "phone_number": phone_number,
                "auth_state": {
                    "stel_ssid": auth_state.stel_ssid,
                    "stel_tsession": auth_state.stel_tsession,
                    "stel_token": auth_state.stel_token,
                    "auth_result": auth_state.auth_result,
                    "login_link": auth_state.login_link,
                    "fragment_cookies": auth_state.fragment_cookies,
                    "user_data": auth_state.user_data,
                    "wallet_connected": auth_state.wallet_connected,
                    "current_step": auth_state.current_step.value
                },
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "user_agent": random.choice(FragmentConstants.USER_AGENTS),
                    "version": "1.0"
                }
            }
            
            # Сериализуем и шифруем данные
            serialized_data = pickle.dumps(session_data)
            encrypted_data = self.fernet.encrypt(serialized_data)
            
            # Сохраняем в файл
            session_file = self.storage_dir / f"{session_id}.session"
            with open(session_file, 'wb') as f:
                f.write(encrypted_data)
            
            auth_state.session_id = session_id
            self.logger.info(f"Сессия сохранена: {session_id} для номера {phone_number}")
            
            return session_id
            
        except Exception as e:
            self.logger.error(f"Ошибка сохранения сессии: {e}")
            raise FragmentBaseError(f"Не удалось сохранить сессию: {e}")
    
    def load_session(self, session_id: str) -> Optional[Dict]:
        """Загрузка зашифрованной сессии"""
        try:
            session_file = self.storage_dir / f"{session_id}.session"
            
            if not session_file.exists():
                self.logger.warning(f"Файл сессии не найден: {session_id}")
                return None
            
            # Читаем и расшифровываем данные
            with open(session_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            session_data = pickle.loads(decrypted_data)
            
            # Восстанавливаем enum
            session_data["auth_state"]["current_step"] = AuthSteps(session_data["auth_state"]["current_step"])
            
            self.logger.info(f"Сессия загружена: {session_id}")
            return session_data
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки сессии {session_id}: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Удаление сессии"""
        try:
            session_file = self.storage_dir / f"{session_id}.session"
            
            if session_file.exists():
                session_file.unlink()
                self.logger.info(f"Сессия удалена: {session_id}")
                return True
            else:
                self.logger.warning(f"Файл сессии для удаления не найден: {session_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Ошибка удаления сессии {session_id}: {e}")
            return False
    
    def list_sessions(self) -> List[Dict]:
        """Список всех сохраненных сессий"""
        sessions = []
        
        try:
            for session_file in self.storage_dir.glob("*.session"):
                session_id = session_file.stem
                session_data = self.load_session(session_id)
                
                if session_data:
                    sessions.append({
                        "session_id": session_id,
                        "phone_number": session_data.get("phone_number", "Unknown"),
                        "created_at": session_data.get("metadata", {}).get("created_at", "Unknown"),
                        "current_step": session_data.get("auth_state", {}).get("current_step", AuthSteps.INITIALIZED)
                    })
            
            self.logger.info(f"Найдено сессий: {len(sessions)}")
            return sessions
            
        except Exception as e:
            self.logger.error(f"Ошибка получения списка сессий: {e}")
            return []
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Очистка устаревших сессий"""
        try:
            deleted_count = 0
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            for session_file in self.storage_dir.glob("*.session"):
                session_data = self.load_session(session_file.stem)
                
                if session_data:
                    created_at_str = session_data.get("metadata", {}).get("created_at")
                    if created_at_str:
                        created_at = datetime.fromisoformat(created_at_str)
                        if created_at < cutoff_time:
                            if self.delete_session(session_file.stem):
                                deleted_count += 1
            
            self.logger.info(f"Удалено устаревших сессий: {deleted_count}")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Ошибка очистки устаревших сессий: {e}")
            return 0


# =============================================================================
# ОСНОВНОЙ КЛИЕНТ HTTP
# =============================================================================

class FragmentHTTPClient:
    """Продвинутый HTTP клиент для работы с Fragment.com и Telegram OAuth"""
    
    def __init__(self, session_manager: SessionManager = None):
        self.session_manager = session_manager or SessionManager()
        self.logger = FragmentLogger("HTTPClient").get_logger()
        
        # Инициализация сессии requests
        self.session = requests.Session()
        self._setup_session()
        
        # Состояние
        self.auth_state = AuthState()
        self.request_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_bytes_downloaded": 0,
            "start_time": datetime.now()
        }
        
        self.logger.info("HTTP клиент Fragment инициализирован")
    
    def _setup_session(self):
        """Настройка HTTP сессии с продвинутыми параметрами"""
        # Случайный User-Agent
        user_agent = random.choice(FragmentConstants.USER_AGENTS)
        
        # Базовые заголовки
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        })
        
        # Настройка адаптера с retry стратегией
        adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=20,
            pool_maxsize=20,
            pool_block=False
        )
        
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Отключаем проверку SSL (для избежания проблем с сертификатами)
        self.session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.logger.debug(f"HTTP сессия настроена с User-Agent: {user_agent[:50]}...")
    
    def _get_oauth_params(self) -> Dict[str, str]:
        """Получение параметров для OAuth запросов"""
        return {
            "bot_id": FragmentConstants.BOT_ID,
            "origin": FragmentConstants.ORIGIN_URL,
            "request_access": FragmentConstants.REQUEST_ACCESS,
            "return_to": FragmentConstants.RETURN_TO_URL,
        }
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Универсальный метод выполнения HTTP запросов с обработкой ошибок и retry логикой"""
        for attempt in range(FragmentConstants.MAX_RETRIES):
            try:
                self.request_stats["total_requests"] += 1
                
                # Добавляем задержку между повторными попытками
                if attempt > 0:
                    delay = FragmentConstants.RETRY_DELAY_BASE * (2 ** (attempt - 1))
                    self.logger.debug(f"Повторная попытка {attempt}/{FragmentConstants.MAX_RETRIES} через {delay} сек")
                    time.sleep(delay)
                
                # Выполняем запрос
                response = self.session.request(
                    method.upper(),
                    url,
                    timeout=FragmentConstants.REQUEST_TIMEOUT,
                    **kwargs
                )
                
                # Обновляем статистику
                if 200 <= response.status_code < 400:
                    self.request_stats["successful_requests"] += 1
                else:
                    self.request_stats["failed_requests"] += 1
                
                self.logger.debug(f"HTTP {method} {url} - Status: {response.status_code}")
                return response
                
            except requests.exceptions.Timeout as e:
                self.request_stats["failed_requests"] += 1
                self.logger.warning(f"Таймаут запроса {method} {url} (попытка {attempt + 1})")
                
                if attempt == FragmentConstants.MAX_RETRIES - 1:
                    raise NetworkError(f"Таймаут после {FragmentConstants.MAX_RETRIES} попыток", url, e)
                    
            except requests.exceptions.ConnectionError as e:
                self.request_stats["failed_requests"] += 1
                self.logger.warning(f"Ошибка соединения {method} {url} (попытка {attempt + 1})")
                
                if attempt == FragmentConstants.MAX_RETRIES - 1:
                    raise NetworkError(f"Ошибка соединения после {FragmentConstants.MAX_RETRIES} попыток", url, e)
                    
            except requests.exceptions.RequestException as e:
                self.request_stats["failed_requests"] += 1
                self.logger.warning(f"Ошибка запроса {method} {url} (попытка {attempt + 1}): {e}")
                
                if attempt == FragmentConstants.MAX_RETRIES - 1:
                    raise NetworkError(f"Ошибка запроса после {FragmentConstants.MAX_RETRIES} попыток", url, e)
        
        # Эта точка никогда не должна достигаться, но для подстраховки
        raise NetworkError(f"Неизвестная ошибка после {FragmentConstants.MAX_RETRIES} попыток", url)
    
    def oauth_get(self, path: str, **kwargs) -> requests.Response:
        """GET запрос к OAuth Telegram"""
        url = f"{FragmentConstants.OAUTH_URL}{path}"
        params = {**self._get_oauth_params(), **kwargs.pop('params', {})}
        return self._make_request('GET', url, params=params, **kwargs)
    
    def oauth_post(self, path: str, **kwargs) -> requests.Response:
        """POST запрос к OAuth Telegram"""
        url = f"{FragmentConstants.OAUTH_URL}{path}"
        params = self._get_oauth_params()
        return self._make_request('POST', url, params=params, **kwargs)
    
    def fragment_get(self, path: str, **kwargs) -> requests.Response:
        """GET запрос к Fragment.com"""
        url = f"{FragmentConstants.FRAGMENT_URL}{path}"
        return self._make_request('GET', url, **kwargs)
    
    def fragment_post(self, path: str, **kwargs) -> requests.Response:
        """POST запрос к Fragment.com"""
        url = f"{FragmentConstants.FRAGMENT_URL}{path}"
        return self._make_request('POST', url, **kwargs)
    
    def fragment_api(self, method: str, data: Dict = None, **kwargs) -> requests.Response:
        """Запрос к API Fragment.com"""
        url = FragmentConstants.FRAGMENT_API_URL
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": FragmentConstants.FRAGMENT_URL,
            "Origin": FragmentConstants.FRAGMENT_URL,
        }
        
        api_data = {"method": method, **(data or {})}
        
        return self._make_request('POST', url, data=api_data, headers=headers, **kwargs)
    
    def save_session(self, phone_number: str) -> str:
        """Сохранение текущей сессии"""
        return self.session_manager.save_session(self.auth_state, phone_number)
    
    def load_session(self, session_id: str) -> bool:
        """Загрузка сессии по ID"""
        session_data = self.session_manager.load_session(session_id)
        
        if session_data:
            # Восстанавливаем состояние авторизации
            auth_data = session_data["auth_state"]
            self.auth_state = AuthState(
                stel_ssid=auth_data["stel_ssid"],
                stel_tsession=auth_data["stel_tsession"],
                stel_token=auth_data["stel_token"],
                auth_result=auth_data["auth_result"],
                login_link=auth_data["login_link"],
                fragment_cookies=auth_data["fragment_cookies"],
                user_data=auth_data["user_data"],
                wallet_connected=auth_data["wallet_connected"],
                current_step=auth_data["current_step"],
                session_id=session_id
            )
            
            # Восстанавливаем куки
            if self.auth_state.fragment_cookies:
                for name, value in self.auth_state.fragment_cookies.items():
                    self.session.cookies.set(name, value)
            
            self.logger.info(f"Сессия восстановлена: {session_id}")
            return True
        
        return False
    
    def get_request_statistics(self) -> Dict[str, Any]:
        """Получение детальной статистики запросов"""
        stats = self.request_stats.copy()
        stats["end_time"] = datetime.now()
        stats["duration"] = str(stats["end_time"] - stats["start_time"])
        stats["success_rate"] = (stats["successful_requests"] / stats["total_requests"] * 100) if stats["total_requests"] > 0 else 0
        
        return stats


# =============================================================================
# СИСТЕМА АВТОРИЗАЦИИ TELEGRAM
# =============================================================================

class TelegramAuthProcessor:
    """Продвинутый процессор авторизации через Telegram OAuth"""
    
    def __init__(self, http_client: FragmentHTTPClient):
        self.client = http_client
        self.logger = FragmentLogger("TelegramAuth").get_logger()
        self.auth_state = http_client.auth_state
        
        # Трекер прогресса авторизации
        self.progress = {
            "current_step": 0,
            "total_steps": 7,
            "steps_completed": [],
            "errors_encountered": []
        }
    
    def _update_progress(self, step_name: str, success: bool = True, error: str = None):
        """Обновление прогресса авторизации"""
        self.progress["current_step"] += 1
        self.progress["steps_completed"].append({
            "step": step_name,
            "success": success,
            "error": error,
            "timestamp": datetime.now().isoformat()
        })
        
        if error:
            self.progress["errors_encountered"].append(error)
        
        progress_percent = (self.progress["current_step"] / self.progress["total_steps"]) * 100
        self.logger.info(f"Прогресс авторизации: {progress_percent:.1f}% - {step_name}")
    
    def initialize_oauth_session(self) -> bool:
        """Инициализация OAuth сессии и получение stel_ssid"""
        try:
            self.logger.info("🔐 Инициализация OAuth сессии...")
            
            with self.logger.log_execution_time("Инициализация OAuth сессии"):
                response = self.client.oauth_get("/auth")
                
                if response.status_code != 200:
                    raise TelegramAuthError(
                        f"Ошибка инициализации сессии: HTTP {response.status_code}",
                        AuthSteps.INITIALIZED,
                        {"status_code": response.status_code, "response_text": response.text[:500]}
                    )
                
                # Извлекаем stel_ssid из кук
                stel_ssid = response.cookies.get("stel_ssid")
                if not stel_ssid:
                    raise TelegramAuthError(
                        "Не удалось получить stel_ssid из cookies",
                        AuthSteps.INITIALIZED,
                        {"cookies": dict(response.cookies)}
                    )
                
                self.auth_state.stel_ssid = stel_ssid
                self.auth_state.current_step = AuthSteps.INITIALIZED
                
                self._update_progress("Инициализация сессии", success=True)
                self.logger.info(f"✅ OAuth сессия инициализирована, stel_ssid: {stel_ssid[:10]}...")
                return True
                
        except Exception as e:
            self._update_progress("Инициализация сессии", success=False, error=str(e))
            raise
    
    def send_phone_number(self, phone_number: str) -> bool:
        """Отправка номера телефона для авторизации"""
        try:
            if not self.auth_state.stel_ssid:
                raise TelegramAuthError("Сессия не инициализирована", AuthSteps.PHONE_SENT)
            
            self.logger.info(f"📱 Отправка номера телефона: {phone_number}")
            
            with self.logger.log_execution_time("Отправка номера телефона"):
                cookies = {"stel_ssid": self.auth_state.stel_ssid}
                data = {"phone": phone_number}
                
                response = self.client.oauth_post("/request", data=data, cookies=cookies)
                
                if response.status_code != 200:
                    raise TelegramAuthError(
                        f"Ошибка отправки номера: HTTP {response.status_code}",
                        AuthSteps.PHONE_SENT,
                        {"status_code": response.status_code, "phone_number": phone_number}
                    )
                
                # Парсим JSON ответ
                try:
                    result = response.json()
                    if result.get("result") != "true":
                        raise TelegramAuthError(
                            f"Ошибка в ответе сервера: {result}",
                            AuthSteps.PHONE_SENT,
                            {"response_data": result}
                        )
                except ValueError as e:
                    raise TelegramAuthError(
                        f"Неверный JSON в ответе: {e}",
                        AuthSteps.PHONE_SENT,
                        {"response_text": response.text[:500]}
                    )
                
                # Сохраняем stel_tsession
                stel_tsession = response.cookies.get("stel_tsession")
                if not stel_tsession:
                    raise TelegramAuthError(
                        "Не удалось получить stel_tsession",
                        AuthSteps.PHONE_SENT,
                        {"cookies": dict(response.cookies)}
                    )
                
                self.auth_state.stel_tsession = stel_tsession
                self.auth_state.current_step = AuthSteps.PHONE_SENT
                
                self._update_progress("Отправка номера телефона", success=True)
                self.logger.info(f"✅ Номер отправлен, stel_tsession: {stel_tsession[:10]}...")
                return True
                
        except Exception as e:
            self._update_progress("Отправка номера телефона", success=False, error=str(e))
            raise
    
    def wait_for_user_confirmation(self, timeout: int = 120) -> bool:
        """Ожидание подтверждения пользователя в Telegram"""
        try:
            if not self.auth_state.stel_tsession:
                raise TelegramAuthError("Номер не отправлен", AuthSteps.CONFIRMED)
            
            self.logger.info("⏳ Ожидание подтверждения в Telegram...")
            self.logger.info("ℹ️  Пожалуйста, подтвердите вход в приложении Telegram")
            
            cookies = {
                "stel_ssid": self.auth_state.stel_ssid,
                "stel_tsession": self.auth_state.stel_tsession
            }
            
            start_time = time.time()
            poll_interval = 3  # Проверяем каждые 3 секунды
            
            with self.logger.log_execution_time("Ожидание подтверждения"):
                while time.time() - start_time < timeout:
                    try:
                        self.logger.debug(f"Проверка подтверждения... (прошло {int(time.time() - start_time)} сек)")
                        
                        response = self.client.oauth_post("/login", data={}, cookies=cookies)
                        
                        if response.status_code == 200:
                            result = response.json()
                            if result.get("result") == "true":
                                # Получаем stel_token
                                stel_token = response.cookies.get("stel_token")
                                if stel_token:
                                    self.auth_state.stel_token = stel_token
                                    self.auth_state.current_step = AuthSteps.CONFIRMED
                                    
                                    self._update_progress("Подтверждение пользователя", success=True)
                                    self.logger.info(f"✅ Подтверждение получено, stel_token: {stel_token[:10]}...")
                                    return True
                        
                        # Ждем перед следующей проверкой
                        time.sleep(poll_interval)
                        
                    except Exception as poll_error:
                        self.logger.warning(f"Ошибка при опросе статуса: {poll_error}")
                        time.sleep(poll_interval)
                
                # Таймаут
                raise TelegramAuthError(
                    f"Таймаут ожидания подтверждения ({timeout} секунд)",
                    AuthSteps.CONFIRMED,
                    {"timeout": timeout, "poll_interval": poll_interval}
                )
                
        except Exception as e:
            self._update_progress("Подтверждение пользователя", success=False, error=str(e))
            raise
    
    def get_authorization_link(self) -> str:
        """Получение ссылки для авторизации с confirm_url"""
        try:
            if not self.auth_state.stel_token:
                raise TelegramAuthError("Подтверждение не получено", AuthSteps.LINK_OBTAINED)
            
            self.logger.info("🔗 Получение ссылки авторизации...")
            
            with self.logger.log_execution_time("Получение ссылки авторизации"):
                cookies = {
                    "stel_ssid": self.auth_state.stel_ssid,
                    "stel_token": self.auth_state.stel_token
                }
                
                headers = {
                    "Referer": f"{FragmentConstants.OAUTH_URL}/auth?{urlencode(self.client._get_oauth_params())}"
                }
                
                response = self.client.oauth_get("", headers=headers, cookies=cookies)
                
                if response.status_code != 200:
                    raise TelegramAuthError(
                        f"Ошибка получения ссылки: HTTP {response.status_code}",
                        AuthSteps.LINK_OBTAINED,
                        {"status_code": response.status_code}
                    )
                
                # Парсим HTML для извлечения confirm_url
                soup = BeautifulSoup(response.text, 'html.parser')
                confirm_url = None
                
                # Ищем confirm_url в JavaScript коде
                for script in soup.find_all('script'):
                    if script.string and 'confirm_url' in script.string:
                        match = re.search(r"var confirm_url = '([^']+)'", script.string)
                        if match:
                            confirm_url = match.group(1)
                            break
                
                if not confirm_url:
                    # Альтернативный поиск
                    for script in soup.find_all('script'):
                        if script.string and 'confirm_url' in script.string:
                            match = re.search(r'confirm_url\s*=\s*["\']([^"\']+)["\']', script.string)
                            if match:
                                confirm_url = match.group(1)
                                break
                
                if not confirm_url:
                    raise TelegramAuthError(
                        "Не удалось найти confirm_url в ответе",
                        AuthSteps.LINK_OBTAINED,
                        {"html_preview": response.text[:1000]}
                    )
                
                # Формируем полную ссылку авторизации
                auth_link = f"{FragmentConstants.OAUTH_URL}{confirm_url}&allow_write=1"
                self.auth_state.current_step = AuthSteps.LINK_OBTAINED
                
                self._update_progress("Получение ссылки авторизации", success=True)
                self.logger.info(f"✅ Ссылка авторизации получена: {auth_link[:80]}...")
                return auth_link
                
        except Exception as e:
            self._update_progress("Получение ссылки авторизации", success=False, error=str(e))
            raise
    
    def process_authorization_callback(self, auth_link: str) -> bool:
        """Обработка callback авторизации с редиректом на Fragment.com"""
        try:
            self.logger.info("🔄 Обработка callback авторизации...")
            
            with self.logger.log_execution_time("Обработка callback авторизации"):
                cookies = {
                    "stel_ssid": self.auth_state.stel_ssid,
                    "stel_token": self.auth_state.stel_token
                }
                
                # Выполняем запрос к ссылке авторизации с разрешением редиректов
                response = self.client.session.get(
                    auth_link,
                    cookies=cookies,
                    headers={"User-Agent": random.choice(FragmentConstants.USER_AGENTS)},
                    allow_redirects=True,
                    timeout=FragmentConstants.REQUEST_TIMEOUT
                )
                
                # Анализируем финальный URL после всех редиректов
                final_url = response.url
                self.logger.debug(f"Финальный URL после редиректов: {final_url}")
                
                # Сохраняем куки от Fragment.com
                fragment_cookies = {}
                for cookie in self.client.session.cookies:
                    if "fragment.com" in cookie.domain or cookie.domain == "":
                        fragment_cookies[cookie.name] = cookie.value
                
                self.auth_state.fragment_cookies = fragment_cookies
                self.auth_state.current_step = AuthSteps.CALLBACK_PROCESSED
                
                self._update_progress("Обработка callback", success=True)
                self.logger.info(f"✅ Callback обработан, получено {len(fragment_cookies)} кук Fragment")
                return True
                
        except Exception as e:
            self._update_progress("Обработка callback", success=False, error=str(e))
            raise
    
    def extract_login_link_from_fragment(self) -> str:
        """Извлечение login-link (tgAuthResult) из главной страницы Fragment.com"""
        try:
            self.logger.info("🔍 Поиск login-link на главной странице Fragment...")
            
            with self.logger.log_execution_time("Извлечение login-link"):
                # Загружаем главную страницу Fragment.com с куками
                response = self.client.fragment_get("")
                
                if response.status_code != 200:
                    raise TelegramAuthError(
                        f"Ошибка загрузки главной страницы: HTTP {response.status_code}",
                        AuthSteps.LOGIN_LINK_EXTRACTED,
                        {"status_code": response.status_code}
                    )
                
                # Парсим HTML для поиска login-link
                soup = BeautifulSoup(response.text, 'html.parser')
                login_link = None
                
                # Поиск 1: В URL фрагменте (hash)
                if "#tgAuthResult=" in response.url:
                    login_link = response.url.split("#tgAuthResult=")[1]
                    self.logger.debug("Login-link найден в URL фрагменте")
                
                # Поиск 2: В JavaScript коде
                if not login_link:
                    for script in soup.find_all('script'):
                        if script.string and 'tgAuthResult' in script.string:
                            # Ищем в различных форматах
                            patterns = [
                                r"tgAuthResult=([^&'\"]+)",
                                r"#tgAuthResult=([^&'\"]+)",
                                r"login-link[^=]*=([^;]+)",
                                r"authResult[^=]*=([^;]+)"
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, script.string)
                                if match:
                                    login_link = match.group(1)
                                    self.logger.debug(f"Login-link найден в JS с паттерном: {pattern}")
                                    break
                            
                            if login_link:
                                break
                
                # Поиск 3: В data-атрибутах
                if not login_link:
                    for element in soup.find_all(attrs={"data-auth": True}):
                        login_link = element.get("data-auth")
                        self.logger.debug("Login-link найден в data-атрибутах")
                        break
                
                if not login_link:
                    raise TelegramAuthError(
                        "Не удалось найти login-link на странице",
                        AuthSteps.LOGIN_LINK_EXTRACTED,
                        {"url": response.url, "html_preview": response.text[:1000]}
                    )
                
                self.auth_state.login_link = login_link
                self.auth_state.current_step = AuthSteps.LOGIN_LINK_EXTRACTED
                
                self._update_progress("Извлечение login-link", success=True)
                self.logger.info(f"✅ Login-link извлечен: {login_link[:50]}...")
                return login_link
                
        except Exception as e:
            self._update_progress("Извлечение login-link", success=False, error=str(e))
            raise
    
    def complete_fragment_authentication(self) -> bool:
        """Завершение авторизации на Fragment.com с использованием login-link"""
        try:
            if not self.auth_state.login_link:
                raise TelegramAuthError("Login-link не получен", AuthSteps.FRAGMENT_AUTHENTICATED)
            
            self.logger.info("🎯 Завершение авторизации на Fragment.com...")
            
            with self.logger.log_execution_time("Завершение авторизации Fragment"):
                # Отправляем запрос к API Fragment для завершения авторизации
                response = self.client.fragment_api("logIn", {
                    "auth": self.auth_state.login_link
                })
                
                if response.status_code != 200:
                    raise FragmentAPIError(
                        f"Ошибка API при авторизации: HTTP {response.status_code}",
                        response.status_code,
                        "logIn"
                    )
                
                # Парсим ответ
                try:
                    result = response.json()
                    
                    if result.get("result") == "true":
                        # Сохраняем данные пользователя
                        user_data = result.get("user", {})
                        self.auth_state.user_data = user_data
                        self.auth_state.current_step = AuthSteps.FRAGMENT_AUTHENTICATED
                        
                        # Обновляем куки
                        for cookie in self.client.session.cookies:
                            if "fragment.com" in cookie.domain:
                                self.auth_state.fragment_cookies[cookie.name] = cookie.value
                        
                        self._update_progress("Авторизация Fragment", success=True)
                        
                        # Логируем информацию о пользователе
                        user_info = {
                            "id": user_data.get("id"),
                            "first_name": user_data.get("first_name"),
                            "last_name": user_data.get("last_name"),
                            "username": user_data.get("username"),
                            "photo_url": user_data.get("photo_url")[:100] + "..." if user_data.get("photo_url") else None
                        }
                        
                        self.logger.info(f"✅ Авторизация успешна! Пользователь: {user_info}")
                        return True
                    else:
                        error_msg = result.get("error", "Unknown error")
                        raise FragmentAPIError(
                            f"Ошибка авторизации: {error_msg}",
                            response.status_code,
                            "logIn"
                        )
                        
                except ValueError as e:
                    raise FragmentAPIError(
                        f"Неверный JSON в ответе: {e}",
                        response.status_code,
                        "logIn"
                    )
                    
        except Exception as e:
            self._update_progress("Авторизация Fragment", success=False, error=str(e))
            raise
    
    def connect_wallet_to_session(self) -> bool:
        """Подключение кошелька к сессии"""
        try:
            self.logger.info("💰 Проверка подключения кошелька...")
            
            with self.logger.log_execution_time("Подключение кошелька"):
                # Загружаем страницу кошелька
                response = self.client.fragment_get("/my/account")
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Ищем индикаторы кошелька
                    wallet_indicators = [
                        soup.find(class_=re.compile(r"wallet|balance|ton-wallet")),
                        soup.find(text=re.compile(r"TON|Wallet|Balance", re.IGNORECASE))
                    ]
                    
                    if any(wallet_indicators):
                        self.auth_state.wallet_connected = True
                        self.auth_state.current_step = AuthSteps.WALLET_CONNECTED
                        
                        self._update_progress("Подключение кошелька", success=True)
                        self.logger.info("✅ Кошелек подключен к сессии")
                        return True
                    else:
                        self.logger.warning("⚠️  Кошелек не обнаружен на странице")
                        return False
                else:
                    self.logger.warning(f"⚠️  Не удалось загрузить страницу кошелька: {response.status_code}")
                    return False
                    
        except Exception as e:
            self._update_progress("Подключение кошелька", success=False, error=str(e))
            self.logger.warning(f"Ошибка проверки кошелька: {e}")
            return False
    
    def execute_complete_auth_flow(self, phone_number: str) -> bool:
        """Выполнение полного процесса авторизации"""
        self.logger.info("🚀 Запуск полного процесса авторизации Telegram OAuth")
        
        try:
            # Основные этапы авторизации
            auth_steps = [
                ("Инициализация OAuth сессии", self.initialize_oauth_session),
                ("Отправка номера телефона", lambda: self.send_phone_number(phone_number)),
                ("Ожидание подтверждения в Telegram", self.wait_for_user_confirmation),
                ("Получение ссылки авторизации", self.get_authorization_link),
            ]
            
            # Выполняем основные этапы
            for step_name, step_func in auth_steps:
                self.logger.info(f"▶️  Выполнение: {step_name}")
                if not step_func():
                    raise TelegramAuthError(f"Ошибка на этапе: {step_name}")
                time.sleep(FragmentConstants.DEFAULT_DELAY)
            
            # Получаем ссылку авторизации
            auth_link = self.get_authorization_link()
            if not auth_link:
                raise TelegramAuthError("Не удалось получить ссылку авторизации")
            
            # Обрабатываем callback
            self.logger.info("▶️  Выполнение: Обработка callback авторизации")
            if not self.process_authorization_callback(auth_link):
                raise TelegramAuthError("Ошибка обработки callback авторизации")
            
            # Извлекаем login-link
            self.logger.info("▶️  Выполнение: Извлечение login-link")
            login_link = self.extract_login_link_from_fragment()
            if not login_link:
                raise TelegramAuthError("Не удалось извлечь login-link")
            
            # Завершаем авторизацию
            self.logger.info("▶️  Выполнение: Завершение авторизации на Fragment")
            if not self.complete_fragment_authentication():
                raise TelegramAuthError("Ошибка завершения авторизации на Fragment")
            
            # Пытаемся подключить кошелек
            self.logger.info("▶️  Выполнение: Проверка кошелька")
            self.connect_wallet_to_session()
            
            # Сохраняем сессию
            self.logger.info("💾 Сохранение сессии...")
            session_id = self.client.save_session(phone_number)
            
            self.auth_state.current_step = AuthSteps.COMPLETED
            self._update_progress("Сохранение сессии", success=True)
            
            self.logger.info(f"✅ Полный процесс авторизации завершен успешно! Session ID: {session_id}")
            
            # Выводим информацию о пользователе
            if self.auth_state.user_data:
                user = self.auth_state.user_data
                print("\n" + "="*50)
                print("✅ АВТОРИЗАЦИЯ УСПЕШНА!")
                print("="*50)
                print(f"👤 Имя: {user.get('first_name', 'N/A')} {user.get('last_name', '')}")
                print(f"📛 Username: @{user.get('username', 'N/A')}")
                print(f"🆔 ID: {user.get('id', 'N/A')}")
                print(f"💰 Кошелек: {'Подключен' if self.auth_state.wallet_connected else 'Не подключен'}")
                print(f"🔐 Session ID: {session_id}")
                print("="*50)
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Критическая ошибка в процессе авторизации: {e}")
            raise
    
    def get_auth_progress_report(self) -> Dict[str, Any]:
        """Получение отчета о прогрессе авторизации"""
        return {
            "progress": self.progress,
            "current_step": self.auth_state.current_step.value,
            "steps_completed": len(self.progress["steps_completed"]),
            "total_steps": self.progress["total_steps"],
            "completion_percentage": (len(self.progress["steps_completed"]) / self.progress["total_steps"]) * 100,
            "errors_count": len(self.progress["errors_encountered"]),
            "user_authenticated": self.auth_state.current_step.value >= AuthSteps.FRAGMENT_AUTHENTICATED.value
        }


# =============================================================================
# СИСТЕМА СКАЧИВАНИЯ САЙТА
# =============================================================================

class FragmentSiteDownloader:
    """Продвинутая система скачивания сайта Fragment.com"""
    
    def __init__(self, http_client: FragmentHTTPClient):
        self.client = http_client
        self.logger = FragmentLogger("SiteDownloader").get_logger()
        
        # Структуры данных для управления скачиванием
        self.downloaded_pages: Set[str] = set()
        self.downloaded_assets: Set[str] = set()
        self.failed_downloads: List[Dict] = []
        self.queued_urls: Queue = Queue()
        self.active_downloads: Set[str] = set()
        
        # Статистика
        self.stats = DownloadStats()
        self.stats.start_time = datetime.now()
        
        # Конфигурация скачивания
        self.excluded_paths = set(FragmentConstants.EXCLUDED_PATHS)
        self.allowed_domains = {'fragment.com', 'oauth.telegram.org'}
        
        # Создание структуры директорий
        self._create_directory_structure()
        
        self.logger.info("Система скачивания Fragment инициализирована")
    
    def _create_directory_structure(self):
        """Создание полной структуры директорий для скачивания"""
        base_dirs = [
            FragmentConstants.BASE_OUTPUT_DIR,
            f"{FragmentConstants.BASE_OUTPUT_DIR}/pages",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/assets/css",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/assets/js",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/assets/images",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/assets/fonts",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/assets/icons",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/data",
            f"{FragmentConstants.BASE_OUTPUT_DIR}/api_responses"
        ]
        
        for directory in base_dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Структура директорий создана в: {FragmentConstants.BASE_OUTPUT_DIR}")
    
    def add_excluded_paths(self, paths: Set[str]):
        """Добавление путей для исключения из скачивания"""
        self.excluded_paths.update(paths)
        self.logger.info(f"Добавлены исключенные пути: {paths}")
    
    def remove_excluded_paths(self, paths: Set[str]):
        """Удаление путей из исключений"""
        self.excluded_paths.difference_update(paths)
        self.logger.info(f"Удалены исключенные пути: {paths}")
    
    def is_path_excluded(self, path: str) -> bool:
        """Проверка, исключен ли путь из скачивания"""
        if not path or path == "/":
            return False
        
        path_lower = path.lower()
        return any(excluded in path_lower for excluded in self.excluded_paths)
    
    def normalize_file_path(self, url_path: str, is_asset: bool = False) -> str:
        """Нормализация пути файла для файловой системы"""
        if not url_path or url_path == "/":
            return "index.html" if not is_asset else "assets/index.html"
        
        # Очистка пути
        clean_path = url_path.lstrip('/')
        
        # Замена недопустимых символов
        clean_path = re.sub(r'[<>:"|?*]', '_', clean_path)
        
        # Обработка директорий и файлов
        if clean_path.endswith('/'):
            clean_path += "index.html"
        elif '.' not in clean_path.split('/')[-1]:
            # Если нет расширения, предполагаем HTML
            clean_path += ".html"
        
        # Определение базовой директории
        base_dir = "assets" if is_asset else "pages"
        
        return f"{FragmentConstants.BASE_OUTPUT_DIR}/{base_dir}/{clean_path}"
    
    def extract_links_from_html(self, html: str, base_url: str) -> Set[str]:
        """Извлечение всех ссылок из HTML контента"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Обрабатываем теги <a>
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            if self._is_valid_internal_link(href):
                links.add(href)
        
        # Обрабатываем теги <link> (CSS и т.д.)
        for link_tag in soup.find_all('link', href=True):
            href = link_tag['href']
            if self._is_valid_asset_link(href):
                links.add(href)
        
        # Обрабатываем теги <script>
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            if self._is_valid_asset_link(src):
                links.add(src)
        
        # Обрабатываем теги <img>
        for img_tag in soup.find_all('img', src=True):
            src = img_tag['src']
            if self._is_valid_asset_link(src):
                links.add(src)
        
        self.logger.debug(f"Извлечено {len(links)} ссылок из {base_url}")
        return links
    
    def _is_valid_internal_link(self, href: str) -> bool:
        """Проверка валидности внутренней ссылки"""
        if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            return False
        
        if href.startswith('http'):
            # Проверяем, относится ли к разрешенным доменам
            return any(domain in href for domain in self.allowed_domains)
        else:
            # Относительные пути
            return not self.is_path_excluded(href)
    
    def _is_valid_asset_link(self, href: str) -> bool:
        """Проверка валидности ссылки на ресурс"""
        if not href:
            return False
        
        # Исключаем data URL и внешние ресурсы
        if href.startswith(('data:', 'http://', 'https://')) and not any(domain in href for domain in self.allowed_domains):
            return False
        
        return not self.is_path_excluded(href)
    
    def download_resource(self, url_path: str, resource_type: str = "page") -> Optional[Tuple[str, int]]:
        """Скачивание ресурса (страницы или ассета)"""
        if self.is_path_excluded(url_path):
            self.logger.debug(f"Пропуск исключенного пути: {url_path}")
            return None
        
        if url_path in self.downloaded_pages or url_path in self.downloaded_assets:
            self.logger.debug(f"Ресурс уже скачан: {url_path}")
            return None
        
        try:
            self.logger.info(f"📥 Скачивание: {url_path}")
            
            # Выполняем запрос
            if resource_type == "page":
                response = self.client.fragment_get(url_path)
            else:
                response = self.client.session.get(
                    f"{FragmentConstants.FRAGMENT_URL}{url_path}",
                    headers={"User-Agent": random.choice(FragmentConstants.USER_AGENTS)}
                )
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                if resource_type == "page" or 'text/html' in content_type:
                    # Обработка HTML страниц
                    return self._save_html_content(url_path, response.text)
                else:
                    # Обработка бинарных ресурсов
                    return self._save_binary_content(url_path, response.content, content_type)
            else:
                self._handle_download_error(url_path, response.status_code, resource_type)
                return None
                
        except Exception as e:
            self._handle_download_exception(url_path, e, resource_type)
            return None
    
    def _save_html_content(self, url_path: str, html_content: str) -> Tuple[str, int]:
        """Сохранение HTML контента с обработкой"""
        save_path = self.normalize_file_path(url_path)
        file_size = len(html_content.encode('utf-8'))
        
        # Создаем директорию если нужно
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # Обрабатываем HTML перед сохранением
        processed_html = self._process_html_content(html_content, url_path)
        
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(processed_html)
        
        self.downloaded_pages.add(url_path)
        self.stats.downloaded_pages += 1
        self.stats.total_size_bytes += file_size
        
        self.logger.debug(f"HTML сохранен: {save_path} ({file_size} bytes)")
        return (save_path, file_size)
    
    def _save_binary_content(self, url_path: str, content: bytes, content_type: str) -> Tuple[str, int]:
        """Сохранение бинарного контента"""
        save_path = self.normalize_file_path(url_path, is_asset=True)
        file_size = len(content)
        
        # Создаем директорию если нужно
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        with open(save_path, 'wb') as f:
            f.write(content)
        
        self.downloaded_assets.add(url_path)
        self.stats.downloaded_assets += 1
        self.stats.total_size_bytes += file_size
        
        self.logger.debug(f"Ресурс сохранен: {save_path} ({file_size} bytes, {content_type})")
        return (save_path, file_size)
    
    def _process_html_content(self, html: str, base_url: str) -> str:
        """Обработка HTML контента перед сохранением"""
        soup = BeautifulSoup(html, 'html.parser')
        base_dir = base_url if base_url.endswith('/') else os.path.dirname(base_url) + '/'
        
        # Обработка CSS ссылок
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href']
            if href.startswith('/'):
                asset_path = f"/assets{href}"
                link['href'] = asset_path
                self._queue_asset_download(href)
        
        # Обработка JavaScript
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith('/'):
                asset_path = f"/assets{src}"
                script['src'] = asset_path
                self._queue_asset_download(src)
        
        # Обработка изображений
        for img in soup.find_all('img', src=True):
            src = img['src']
            if src.startswith('/'):
                asset_path = f"/assets{src}"
                img['src'] = asset_path
                self._queue_asset_download(src)
        
        return str(soup)
    
    def _queue_asset_download(self, asset_path: str):
        """Добавление ресурса в очередь для скачивания"""
        if (asset_path not in self.downloaded_assets and 
            asset_path not in self.active_downloads and
            not self.is_path_excluded(asset_path)):
            
            self.active_downloads.add(asset_path)
            threading.Thread(
                target=self._download_asset_worker,
                args=(asset_path,),
                daemon=True
            ).start()
    
    def _download_asset_worker(self, asset_path: str):
        """Воркер для скачивания ресурсов"""
        try:
            self.download_resource(asset_path, "asset")
        finally:
            self.active_downloads.discard(asset_path)
    
    def _handle_download_error(self, url_path: str, status_code: int, resource_type: str):
        """Обработка ошибок скачивания"""
        error_info = {
            "url": url_path,
            "status_code": status_code,
            "resource_type": resource_type,
            "timestamp": datetime.now().isoformat(),
            "error_type": "HTTP_ERROR"
        }
        
        self.failed_downloads.append(error_info)
        self.stats.errors += 1
        
        self.logger.warning(f"Ошибка скачивания {url_path}: HTTP {status_code}")
    
    def _handle_download_exception(self, url_path: str, exception: Exception, resource_type: str):
        """Обработка исключений при скачивании"""
        error_info = {
            "url": url_path,
            "error": str(exception),
            "resource_type": resource_type,
            "timestamp": datetime.now().isoformat(),
            "error_type": "EXCEPTION"
        }
        
        self.failed_downloads.append(error_info)
        self.stats.errors += 1
        
        self.logger.error(f"Исключение при скачивании {url_path}: {exception}")
    
    def crawl_site(self, start_paths: List[str], max_depth: int = FragmentConstants.MAX_DEPTH):
        """Рекурсивный обход и скачивание сайта"""
        self.logger.info(f"🌐 Начало обхода сайта с глубиной {max_depth}")
        
        # Добавляем начальные пути в очередь
        for path in start_paths:
            if not self.is_path_excluded(path):
                self.queued_urls.put((path, 0))
                self.stats.total_pages += 1
        
        # Запускаем воркеры для параллельного скачивания
        workers = []
        for i in range(FragmentConstants.CONCURRENT_WORKERS):
            worker = threading.Thread(
                target=self._crawl_worker,
                args=(max_depth,),
                name=f"DownloadWorker-{i}",
                daemon=True
            )
            worker.start()
            workers.append(worker)
        
        # Ожидаем завершения очереди
        self.queued_urls.join()
        
        # Даем время завершиться воркерам
        self.logger.info("Ожидание завершения воркеров...")
        time.sleep(5)
        
        self.stats.end_time = datetime.now()
        self.logger.info("Обход сайта завершен")
    
    def _crawl_worker(self, max_depth: int):
        """Воркер для рекурсивного обхода"""
        while True:
            try:
                url_path, depth = self.queued_urls.get(timeout=30)
                
                if depth <= max_depth and url_path not in self.downloaded_pages:
                    result = self.download_resource(url_path, "page")
                    
                    if result and depth < max_depth:
                        save_path, _ = result
                        
                        # Читаем сохраненный HTML для извлечения ссылок
                        try:
                            with open(save_path, 'r', encoding='utf-8') as f:
                                html_content = f.read()
                            
                            # Извлекаем ссылки из HTML
                            new_links = self.extract_links_from_html(html_content, url_path)
                            
                            # Добавляем новые ссылки в очередь
                            for link in new_links:
                                if (link not in self.downloaded_pages and 
                                    not self.is_path_excluded(link)):
                                    self.queued_urls.put((link, depth + 1))
                                    self.stats.total_pages += 1
                            
                        except Exception as e:
                            self.logger.error(f"Ошибка обработки {save_path}: {e}")
                
                self.queued_urls.task_done()
                time.sleep(FragmentConstants.DEFAULT_DELAY)
                
            except Empty:
                break
            except Exception as e:
                self.logger.error(f"Ошибка в воркере: {e}")
                self.queued_urls.task_done()
    
    def generate_download_report(self) -> Dict[str, Any]:
        """Генерация детального отчета о скачивании"""
        if not self.stats.end_time:
            self.stats.end_time = datetime.now()
        
        report = {
            "download_statistics": {
                "total_pages": self.stats.total_pages,
                "downloaded_pages": self.stats.downloaded_pages,
                "downloaded_assets": self.stats.downloaded_assets,
                "total_size_mb": self.stats.total_size_bytes / 1024 / 1024,
                "errors_count": self.stats.errors,
                "success_rate_percentage": self.stats.success_rate,
                "start_time": self.stats.start_time.isoformat(),
                "end_time": self.stats.end_time.isoformat(),
                "duration_seconds": self.stats.duration.total_seconds() if self.stats.duration else 0
            },
            "downloaded_pages_list": list(self.downloaded_pages),
            "downloaded_assets_list": list(self.downloaded_assets),
            "failed_downloads": self.failed_downloads,
            "excluded_paths": list(self.excluded_paths),
            "session_info": {
                "user_authenticated": self.client.auth_state.user_data is not None,
                "wallet_connected": self.client.auth_state.wallet_connected,
                "user_data": self.client.auth_state.user_data
            },
            "generated_at": datetime.now().isoformat()
        }
        
        # Сохраняем отчет в файл
        report_file = f"{FragmentConstants.BASE_OUTPUT_DIR}/data/download_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        return report
    
    def print_summary_report(self):
        """Печать сводного отчета в консоль"""
        if not self.stats.end_time:
            self.stats.end_time = datetime.now()
        
        duration = self.stats.duration
        hours = duration.seconds // 3600 if duration else 0
        minutes = (duration.seconds % 3600) // 60 if duration else 0
        seconds = duration.seconds % 60 if duration else 0
        
        print("\n" + "="*70)
        print("📊 ОТЧЕТ О СКАЧИВАНИИ FRAGMENT.COM")
        print("="*70)
        print(f"📅 Время начала: {self.stats.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"⏰ Время окончания: {self.stats.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"⏱️  Общее время: {hours:02d}:{minutes:02d}:{seconds:02d}")
        print(f"📄 Скачано страниц: {self.stats.downloaded_pages}/{self.stats.total_pages}")
        print(f"🖼️  Скачано ресурсов: {self.stats.downloaded_assets}")
        print(f"💾 Общий размер: {self.stats.total_size_bytes / 1024 / 1024:.2f} MB")
        print(f"❌ Ошибок: {self.stats.errors}")
        print(f"📈 Успешность: {self.stats.success_rate:.1f}%")
        print(f"📁 Директория: {FragmentConstants.BASE_OUTPUT_DIR}")
        print("="*70)


# =============================================================================
# ГЛАВНЫЙ КООРДИНАТОР
# =============================================================================

class FragmentCoordinator:
    """Главный координатор для управления всем процессом"""
    
    def __init__(self):
        self.session_manager = SessionManager()
        self.http_client = FragmentHTTPClient(self.session_manager)
        self.auth_processor = TelegramAuthProcessor(self.http_client)
        self.downloader = FragmentSiteDownloader(self.http_client)
        self.logger = FragmentLogger("Coordinator").get_logger()
        
        self.is_authenticated = False
        self.current_session_id = None
        
        self.logger.info("Координатор Fragment инициализирован")
    
    def interactive_phone_input(self) -> str:
        """Интерактивный ввод номера телефона"""
        print("\n" + "="*50)
        print("🔐 АВТОРИЗАЦИЯ FRAGMENT.COM")
        print("="*50)
        
        while True:
            phone = input("Введите номер телефона в международном формате (например, +79123456789): ").strip()
            
            if not phone:
                print("❌ Номер телефона не может быть пустым")
                continue
            
            if not phone.startswith('+'):
                print("❌ Номер должен начинаться с '+' (международный формат)")
                continue
            
            # Базовая валидация номера
            if len(phone) < 10:
                print("❌ Номер телефона слишком короткий")
                continue
            
            confirm = input(f"Подтвердите номер {phone}? (y/N): ").strip().lower()
            if confirm in ('y', 'yes', 'д', 'да'):
                return phone
            else:
                print("Ввод отменен, попробуйте снова")
    
    def list_available_sessions(self):
        """Показать список доступных сессий"""
        sessions = self.session_manager.list_sessions()
        
        if not sessions:
            print("❌ Нет сохраненных сессий")
            return None
        
        print("\n" + "="*50)
        print("💾 СОХРАНЕННЫЕ СЕССИИ")
        print("="*50)
        
        for i, session in enumerate(sessions, 1):
            print(f"{i}. Номер: {session['phone_number']}")
            print(f"   Session ID: {session['session_id']}")
            print(f"   Создана: {session['created_at']}")
            print(f"   Статус: {session['current_step'].value}")
            print()
        
        return sessions
    
    def interactive_session_selection(self) -> Optional[str]:
        """Интерактивный выбор сессии"""
        sessions = self.list_available_sessions()
        
        if not sessions:
            return None
        
        while True:
            try:
                choice = input("Выберите сессию (номер) или 'n' для новой авторизации: ").strip()
                
                if choice.lower() in ('n', 'н', 'new'):
                    return None
                
                index = int(choice) - 1
                if 0 <= index < len(sessions):
                    return sessions[index]['session_id']
                else:
                    print("❌ Неверный выбор")
                    
            except ValueError:
                print("❌ Введите число или 'n'")
            except KeyboardInterrupt:
                print("\nПрервано пользователем")
                return None
    
    def perform_authentication(self, phone_number: str = None) -> bool:
        """Выполнение процесса авторизации"""
        try:
            if not phone_number:
                phone_number = self.interactive_phone_input()
            
            self.logger.info(f"Начало авторизации для номера: {phone_number}")
            
            # Выполняем полный процесс авторизации
            success = self.auth_processor.execute_complete_auth_flow(phone_number)
            
            if success:
                self.is_authenticated = True
                self.current_session_id = self.http_client.auth_state.session_id
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Ошибка авторизации: {e}")
            print(f"❌ Ошибка авторизации: {e}")
            return False
    
    def load_existing_session(self, session_id: str) -> bool:
        """Загрузка существующей сессии"""
        try:
            self.logger.info(f"Попытка загрузки сессии: {session_id}")
            
            if self.http_client.load_session(session_id):
                # Проверяем валидность сессии
                auth_state = self.http_client.auth_state
                
                if auth_state.current_step.value >= AuthSteps.FRAGMENT_AUTHENTICATED.value:
                    self.is_authenticated = True
                    self.current_session_id = session_id
                    
                    self.logger.info(f"Сессия загружена и валидна: {session_id}")
                    print(f"✅ Сессия загружена: {auth_state.user_data.get('first_name', 'User')}")
                    return True
                else:
                    self.logger.warning(f"Сессия не завершена: {auth_state.current_step.value}")
                    print("❌ Сессия не завершена, требуется повторная авторизация")
                    return False
            else:
                self.logger.error(f"Не удалось загрузить сессию: {session_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Ошибка загрузки сессии: {e}")
            return False
    
    def interactive_download_setup(self):
        """Интерактивная настройка параметров скачивания"""
        print("\n" + "="*50)
        print("🌐 НАСТРОЙКА СКАЧИВАНИЯ")
        print("="*50)
        
        # Выбор разделов для скачивания
        default_sections = [
            '/', '/my/account', '/my/wallet', '/numbers', 
            '/usernames', '/auctions', '/ads/topup', '/settings'
        ]
        
        print("Доступные разделы по умолчанию:")
        for i, section in enumerate(default_sections, 1):
            print(f"  {i}. {section}")
        
        print("\nДобавить дополнительные пути? (y/N): ")
        choice = input().strip().lower()
        
        download_paths = default_sections.copy()
        
        if choice in ('y', 'yes', 'д', 'да'):
            print("Введите дополнительные пути (по одному в строке, пустая строка для завершения):")
            while True:
                path = input().strip()
                if not path:
                    break
                if path.startswith('/'):
                    download_paths.append(path)
                else:
                    print("❌ Путь должен начинаться с '/'")
        
        # Настройка исключений
        print(f"\nТекущие исключения: {self.downloader.excluded_paths}")
        print("Добавить дополнительные исключения? (y/N): ")
        choice = input().strip().lower()
        
        if choice in ('y', 'yes', 'д', 'да'):
            print("Введите пути для исключения (через запятую):")
            excluded_input = input().strip()
            if excluded_input:
                new_exclusions = {path.strip() for path in excluded_input.split(',')}
                self.downloader.add_excluded_paths(new_exclusions)
        
        # Глубина скачивания
        print(f"\nТекущая глубина скачивания: {FragmentConstants.MAX_DEPTH}")
        print("Изменить глубину? (y/N): ")
        choice = input().strip().lower()
        
        max_depth = FragmentConstants.MAX_DEPTH
        if choice in ('y', 'yes', 'д', 'да'):
            try:
                new_depth = int(input("Новая глубина (1-5): ").strip())
                if 1 <= new_depth <= 5:
                    max_depth = new_depth
                else:
                    print("❌ Глубина должна быть от 1 до 5, используется значение по умолчанию")
            except ValueError:
                print("❌ Неверное число, используется значение по умолчанию")
        
        return download_paths, max_depth
    
    def execute_site_download(self, download_paths: List[str], max_depth: int = None):
        """Выполнение процесса скачивания сайта"""
        if not self.is_authenticated:
            print("❌ Не авторизован. Сначала выполните авторизацию.")
            return False
        
        try:
            self.logger.info(f"Начало скачивания {len(download_paths)} путей с глубиной {max_depth}")
            
            print(f"\n🚀 Начало скачивания {len(download_paths)} разделов...")
            print("Это может занять несколько минут в зависимости от объема данных.")
            
            # Запускаем скачивание
            self.downloader.crawl_site(
                download_paths, 
                max_depth=max_depth or FragmentConstants.MAX_DEPTH
            )
            
            # Генерируем отчеты
            self.downloader.generate_download_report()
            self.downloader.print_summary_report()
            
            # Сохраняем обновленную сессию
            if self.current_session_id:
                sessions = self.session_manager.list_sessions()
                phone_number = None
                for session in sessions:
                    if session['session_id'] == self.current_session_id:
                        phone_number = session['phone_number']
                        break
                
                if phone_number:
                    self.http_client.save_session(phone_number)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка скачивания: {e}")
            print(f"❌ Ошибка скачивания: {e}")
            return False
    
    def run_interactive_mode(self):
        """Запуск интерактивного режима"""
        try:
            print("\n" + "="*60)
            print("🔄 FRAGMENT.COM COMPLETE SITE COPIER")
            print("="*60)
            
            # Шаг 1: Авторизация
            print("\n1. 🔐 АВТОРИЗАЦИЯ")
            print("-" * 30)
            
            session_choice = self.interactive_session_selection()
            
            if session_choice:
                # Пытаемся загрузить существующую сессию
                if not self.load_existing_session(session_choice):
                    print("❌ Не удалось загрузить сессию, требуется новая авторизация")
                    if not self.perform_authentication():
                        return False
            else:
                # Новая авторизация
                if not self.perform_authentication():
                    return False
            
            # Шаг 2: Настройка скачивания
            print("\n2. 🌐 НАСТРОЙКА СКАЧИВАНИЯ")
            print("-" * 30)
            
            download_paths, max_depth = self.interactive_download_setup()
            
            # Шаг 3: Скачивание
            print("\n3. 📥 ВЫПОЛНЕНИЕ СКАЧИВАНИЯ")
            print("-" * 30)
            
            success = self.execute_site_download(download_paths, max_depth)
            
            if success:
                print("\n✅ ПРОЦЕСС ЗАВЕРШЕН УСПЕШНО!")
                print(f"📁 Файлы сохранены в: {FragmentConstants.BASE_OUTPUT_DIR}")
            else:
                print("\n❌ ПРОЦЕСС ЗАВЕРШЕН С ОШИБКАМИ")
            
            return success
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Прервано пользователем")
            return False
        except Exception as e:
            self.logger.error(f"Критическая ошибка в интерактивном режиме: {e}")
            print(f"❌ Критическая ошибка: {e}")
            return False


# =============================================================================
# ТОЧКА ВХОДА
# =============================================================================

def main():
    """Главная функция приложения"""
    try:
        # Создаем координатор и запускаем интерактивный режим
        coordinator = FragmentCoordinator()
        success = coordinator.run_interactive_mode()
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        logging.getLogger("Main").error(f"Критическая ошибка: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)