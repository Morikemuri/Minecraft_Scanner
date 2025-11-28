#!/usr/bin/env python3
"""
Библиотека защиты для сканера
Обеспечивает анти-анализ, шифрование и проверку целостности
"""
import ctypes
import os
import sys
import time
import hashlib
import hmac
from base64 import b64encode, b64decode
import logging
import subprocess

logger = logging.getLogger(__name__)

class AntiDebug:
    """Методы противодействия отладке и анализу"""
    
    @staticmethod
    def check_debugger():
        """Проверяет наличие активного отладчика"""
        try:
            # Windows API IsDebuggerPresent
            is_debugged = ctypes.windll.kernel32.IsDebuggerPresent()
            if is_debugged:
                logger.warning("[SECURITY] Debugger detected!")
                return True
            return False
        except Exception as e:
            logger.debug(f"Debugger check error: {e}")
            return False

    @staticmethod
    def check_remote_debugger():
        """Check using CheckRemoteDebuggerPresent (may catch debuggers that bypass IsDebuggerPresent)"""
        try:
            is_present = ctypes.c_int(0)
            res = ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(is_present))
            if res and is_present.value != 0:
                logger.warning("[SECURITY] Remote debugger detected via CheckRemoteDebuggerPresent")
                return True
            return False
        except Exception as e:
            logger.debug(f"Remote debugger check error: {e}")
            return False
    
    @staticmethod
    def check_virtual_machine():
        """Проверяет признаки виртуальной машины"""
        vm_signatures = [
            "VirtualBox",
            "VBOX",
            "VMware",
            "QEMU",
            "Xen",
            "Hyper-V",
            "KVM",
            "Bochs"
        ]
        
        try:
            # Проверяем процессы
            import subprocess
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            for sig in vm_signatures:
                if sig.lower() in result.stdout.lower():
                    logger.warning(f"[SECURITY] VM detected: {sig}")
                    return True
            
            # Проверяем реестр
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SYSTEM\CurrentControlSet\Services\VBoxGuest")
                winreg.CloseKey(key)
                logger.warning("[SECURITY] VirtualBox detected in registry")
                return True
            except:
                pass
            
            return False
        except Exception as e:
            logger.debug(f"VM check error: {e}")
            return False

    @staticmethod
    def check_timing_anomaly():
        """Simple timing anomaly check - sandboxes often tamper with Sleep/timing"""
        try:
            start = time.perf_counter()
            time.sleep(0.05)
            elapsed = time.perf_counter() - start
            # If sleep returns almost instantly, mark suspicious
            if elapsed < 0.02:
                logger.warning(f"[SECURITY] Timing anomaly detected: sleep took {elapsed:.6f}s")
                return True
            return False
        except Exception as e:
            logger.debug(f"Timing check error: {e}")
            return False

    @staticmethod
    def check_api_hooks():
        """Detect simple inline hooks by inspecting first bytes of common API functions"""
        try:
            suspicious = []
            names = [
                ('IsDebuggerPresent', ctypes.windll.kernel32.IsDebuggerPresent),
                ('GetProcAddress', ctypes.windll.kernel32.GetProcAddress),
                ('LoadLibraryA', ctypes.windll.kernel32.LoadLibraryA),
                ('VirtualProtect', ctypes.windll.kernel32.VirtualProtect)
            ]

            for name, func in names:
                try:
                    addr = ctypes.cast(func, ctypes.c_void_p).value
                    if not addr:
                        continue
                    first = ctypes.string_at(addr, 1)
                    # 0xE9 or 0xE8 => JMP/CALL (inline hook)
                    if first in (b"\xe9", b"\xe8") or first == b"\xff":
                        logger.warning(f"[SECURITY] Possible API hook detected on {name} (first byte: {first.hex()})")
                        suspicious.append(name)
                except Exception:
                    continue

            return len(suspicious) > 0
        except Exception as e:
            logger.debug(f"API hook check error: {e}")
            return False

    @staticmethod
    def check_sandbox_processes():
        """Look for common sandbox/analysis processes (any.run, cuckoo, etc.)"""
        try:
            procs = []
            r = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=5)
            txt = r.stdout.lower()
            for sig in ("anyrun", "any.run", "cuckoo", "sandbox", "joebox", "joe-box", "vboxservice"):
                if sig in txt:
                    logger.warning(f"[SECURITY] Sandbox/analysis process signature detected: {sig}")
                    procs.append(sig)
            return len(procs) > 0
        except Exception as e:
            logger.debug(f"Sandbox process check error: {e}")
            return False

    @staticmethod
    def check_pyinstaller_unpack():
        """Detect running unpacked from PyInstaller temporary folder (simple heuristic)"""
        try:
            if getattr(sys, 'frozen', False):
                # Running as bundled exe - check _MEIPASS path
                meipass = getattr(sys, '_MEIPASS', None)
                if meipass and os.path.realpath(meipass).lower().startswith(os.getenv('temp','').lower()):
                    logger.warning("[SECURITY] Running from PyInstaller temp extraction (possible unpacking)")
                    return True
            return False
        except Exception as e:
            logger.debug(f"PyInstaller unpack check error: {e}")
            return False
    
    @staticmethod
    def check_antivirus_hooks():
        """Проверяет наличие процессов антивирусов"""
        av_processes = [
            "mbam.exe",           # Malwarebytes
            "avgui.exe",          # AVG
            "avp.exe",            # Kaspersky
            "avast.exe",          # Avast
            "mcshield.exe",       # McAfee
            "egui.exe",           # Eset
            "fsav.exe",           # F-Secure
            "wdfilter.sys"        # Windows Defender
        ]
        
        try:
            import subprocess
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            for av in av_processes:
                if av.lower() in result.stdout.lower():
                    logger.debug(f"[INFO] Security software detected: {av}")
                    return True
            return False
        except Exception as e:
            logger.debug(f"AV check error: {e}")
            return False

class StringEncryption:
    """Шифрование строк во время выполнения"""
    
    @staticmethod
    def xor_crypt(data, key):
        """Простой XOR шифр для обфускации строк"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result)
    
    @staticmethod
    def encrypt_string(plaintext, key=None):
        """Шифрует строку для обфускации"""
        if key is None:
            key = b"DEFAULT_SECURITY_KEY_2024"
        
        encrypted = StringEncryption.xor_crypt(plaintext, key)
        return b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_string(encrypted, key=None):
        """Расшифровывает строку"""
        if key is None:
            key = b"DEFAULT_SECURITY_KEY_2024"
        
        try:
            encrypted_bytes = b64decode(encrypted)
            decrypted = StringEncryption.xor_crypt(encrypted_bytes, key)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

class IntegrityCheck:
    """Проверка целостности файла"""
    
    @staticmethod
    def compute_hmac(file_path, key=None):
        """Вычисляет HMAC-SHA256 для файла"""
        if key is None:
            key = b"INTEGRITY_CHECK_KEY_2024"
        
        try:
            h = hmac.new(key, digestmod=hashlib.sha256)
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.error(f"HMAC computation error: {e}")
            return None
    
    @staticmethod
    def verify_integrity(file_path, expected_hmac, key=None):
        """Проверяет целостность файла"""
        computed = IntegrityCheck.compute_hmac(file_path, key)
        
        if computed is None:
            logger.error("[SECURITY] Could not compute HMAC!")
            return False
        
        if not hmac.compare_digest(computed, expected_hmac):
            logger.error("[SECURITY] File integrity check FAILED!")
            logger.error(f"Expected: {expected_hmac}")
            logger.error(f"Computed: {computed}")
            return False
        
        logger.info("[SECURITY] File integrity verified successfully")
        return True
    
    @staticmethod
    def self_destruct():
        """Удаляет себя при компрометации"""
        try:
            script_path = os.path.abspath(__file__)
            # Переименовываем в .bak и затем удаляем
            temp_path = script_path + ".bak"
            os.rename(script_path, temp_path)
            os.remove(temp_path)
            logger.info("[SECURITY] Self-destruct initiated!")
        except Exception as e:
            logger.error(f"Self-destruct error: {e}")

class SecurityMonitor:
    """Мониторинг безопасности во время выполнения"""
    
    def __init__(self, strict_mode=False):
        """
        strict_mode=True: прекращает работу при обнаружении угрозы
        strict_mode=False: выводит предупреждение, но продолжает
        """
        self.strict_mode = strict_mode
        self.threats = []
    
    def run_checks(self):
        """Выполняет все проверки безопасности"""
        logger.info("Running security checks...")
        
        # Проверка отладчика
        if AntiDebug.check_debugger():
            self.threats.append("Debugger detected")
            if self.strict_mode:
                logger.critical("[SECURITY] Debugger detected - shutting down!")
                return False
        
        # Проверка ВМ
        if AntiDebug.check_virtual_machine():
            self.threats.append("Virtual machine detected")
            if self.strict_mode:
                logger.critical("[SECURITY] VM detected - shutting down!")
                return False
        
        # Проверка антивируса (информационно)
        if AntiDebug.check_antivirus_hooks():
            self.threats.append("Antivirus detected (info only)")
        
        if self.threats:
            logger.warning(f"[SECURITY] Detected {len(self.threats)} threat(s):")
            for threat in self.threats:
                logger.warning(f"  - {threat}")
        else:
            logger.info("[SECURITY] All checks passed!")
        
        return True
    
    def get_threat_summary(self):
        """Возвращает резюме обнаруженных угроз"""
        return self.threats

# Функции для простого использования
def init_security(strict_mode=False):
    """Инициализирует систему безопасности"""
    monitor = SecurityMonitor(strict_mode=strict_mode)
    if not monitor.run_checks():
        raise SecurityError("Security checks failed!")
    return monitor

def encrypt_sensitive_strings():
    """Генерирует зашифрованные строки для использования в коде"""
    sensitive = {
        "hack": StringEncryption.encrypt_string("hack"),
        "cheat": StringEncryption.encrypt_string("cheat"),
        "client": StringEncryption.encrypt_string("client"),
        "wurst": StringEncryption.encrypt_string("wurst"),
        "bounce": StringEncryption.encrypt_string("bounce"),
        ".config": StringEncryption.encrypt_string(".config"),
        ".bind": StringEncryption.encrypt_string(".bind"),
        ".panic": StringEncryption.encrypt_string(".panic"),
        ".toggle": StringEncryption.encrypt_string(".toggle"),
        ".module": StringEncryption.encrypt_string(".module"),
        ".cmd": StringEncryption.encrypt_string(".cmd"),
    }
    
    print("# Зашифрованные строки для использования в scanner:")
    for name, encrypted in sensitive.items():
        print(f"{name} = '{encrypted}'")
    
    return sensitive

class SecurityError(Exception):
    """Исключение безопасности"""
    pass
