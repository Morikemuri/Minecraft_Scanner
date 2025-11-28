#!/usr/bin/env python3
"""
Генератор защиты для minecraft_scanner.py
Запускается автоматически перед компиляцией
"""
import hashlib
from datetime import datetime, timedelta
import os
import sys
import logging

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def compute_file_hash(file_path):
    """Вычисляет SHA256 хэш файла"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Failed to compute hash: {e}")
        return None

def update_uac_check():
    """Обновляет check_admin функцию на версию с явной обработкой ошибок"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scanner_path = os.path.join(script_dir, 'minecraft_scanner.py')
    
    try:
        with open(scanner_path, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.debug("Successfully read scanner file")
        return True
    except Exception as e:
        logger.error(f"Failed to read scanner file: {e}")
        return False

def inject_security(file_path, days_valid=365):
    """Внедряет параметры защиты в файл"""
    try:
        # Генерируем дату истечения
        expiry = (datetime.now() + timedelta(days=days_valid)).isoformat()
        build_date = datetime.now().isoformat()
        
        # Читаем файл
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Вычисляем SHA256 хэш исходного файла
        file_hash = compute_file_hash(file_path)
        
        # Вычисляем HMAC для проверки целостности
        import hmac
        import hashlib
        hmac_key = b"MINECRAFT_SCANNER_SECURITY_2024"
        h = hmac.new(hmac_key, file_path.encode(), hashlib.sha256)
        file_hmac = h.hexdigest()
        
        # Заменяем плейсхолдеры
        content = content.replace('__BUILD_DATE__', build_date)
        content = content.replace('__EXPIRY_DATE__', expiry)
        content = content.replace('__BUILD_HASH__', file_hash[:32])
        content = content.replace('__BUILD_HMAC__', file_hmac)
        
        if file_hash:
            logger.info(f"File hash computed: {file_hash[:16]}...")
        
        # Записываем обновленный файл
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Security injected into {os.path.basename(file_path)}")
        logger.info(f"Build date:  {build_date}")
        logger.info(f"Expiry date: {expiry}")
        logger.info(f"File hash:   {file_hash[:16]}...")
        logger.info(f"File HMAC:   {file_hmac[:16]}...")
        return True
    except Exception as e:
        logger.error(f"Failed to inject security: {e}")
        return False

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scanner_path = os.path.join(script_dir, 'minecraft_scanner.py')
    
    if not os.path.exists(scanner_path):
        logger.error("minecraft_scanner.py not found!")
        sys.exit(1)
    
    try:
        # Обновляем check_admin функцию
        if not update_uac_check():
            logger.warning("UAC check update skipped")
        
        # Внедряем параметры защиты
        days = 365
        try:
            if len(sys.argv) > 1:
                days = int(sys.argv[1])
                if days < 0 or days > 3650:
                    logger.warning(f"Days {days} out of range, using 365")
                    days = 365
        except ValueError as e:
            logger.warning(f"Invalid days argument: {e}, using 365")
            days = 365
        
        if inject_security(scanner_path, days):
            logger.info("Ready for compilation!")
        else:
            logger.error("Security injection failed!")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
