#!/usr/bin/env python3
import os,sys,json,winreg,subprocess,re,ctypes
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

if sys.platform!="win32":print("Windows only!");sys.exit(1)

# Импорт библиотеки защиты
try:
    from security_lib import SecurityMonitor, IntegrityCheck, AntiDebug
    SECURITY_ENABLED = True
    logger.info("Security library loaded successfully")
except ImportError:
    SECURITY_ENABLED = False
    logger.warning("Security library not found - running without protection")

def check_admin():
    """Явный запрос прав администратора"""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.info("Admin rights required - requesting UAC elevation")
            print("[!] Требуются права администратора для полного сканирования")
            print("[!] ✓ Нажми 'ДА' в диалоге UAC для продолжения...\n")
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, 
                                                    " ".join(sys.argv), None, 1)
            except Exception as uac_error:
                logger.error(f"UAC request failed: {uac_error}")
                print(f"[ERROR] UAC request failed: {uac_error}")
            sys.exit(0)
    except Exception as admin_error:
        logger.error(f"Admin check failed: {admin_error}")
        print(f"[ERROR] Admin check failed: {admin_error}")

def init_security():
    """Инициализирует систему безопасности"""
    if not SECURITY_ENABLED:
        logger.warning("Security system disabled")
        return None
    
    try:
        monitor = SecurityMonitor(strict_mode=False)
        if not monitor.run_checks():
            logger.warning("Security checks revealed potential issues")
        return monitor
    except Exception as e:
        logger.error(f"Security initialization failed: {e}")
        return None

class MalwareDetector:
    def __init__(self):
        check_admin()
        
        # Инициализируем безопасность
        self.security_monitor = init_security()
        
        self.user=os.getenv("USERNAME")
        self.path=os.getenv("USERPROFILE")
        self.findings=defaultdict(list)
        self.stats={"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        self.start_time=datetime.now()
        admin = "YES" if ctypes.windll.shell32.IsUserAnAdmin() else "NO"
        print(f"\n[INFO] Running as administrator: {admin}")
        
        # Выводим информацию о безопасности
        if self.security_monitor:
            threats = self.security_monitor.get_threat_summary()
            if threats:
                print(f"[!] Security notices: {len(threats)} detected")
                for threat in threats:
                    print(f"    - {threat}")
        print()
    
    def report(self,cat,sev,msg,det=""):
        self.findings[cat].append({"severity":sev,"message":msg,"details":det,"time":datetime.now().isoformat()})
        self.stats[sev]+=1
        icon={"CRITICAL":"⛔","HIGH":"🔴","MEDIUM":"🟡","LOW":"🔵"}.get(sev)
        print(f"{icon} [{sev}] {msg}")
    
    def scan_mods(self):
        mp=f"{self.path}\\AppData\\Roaming\\.minecraft\\mods"
        if not os.path.exists(mp):return
        try:
            for file in os.listdir(mp):
                if file.lower().endswith(".jar"):
                    if any(k in file.lower() for k in ["hack","cheat","client","wurst","bounce"]):
                        self.report("Mods","CRITICAL",f"Suspicious JAR: {file}",mp)
        except Exception as scan_error:
            print(f"[DEBUG] scan_mods error: {type(scan_error).__name__}: {scan_error}")
    
    def scan_clients(self):
        mc=f"{self.path}\\AppData\\Roaming\\.minecraft"
        ad=f"{self.path}\\AppData\\Roaming"
        clients={"Wurst":[f"{mc}\\wurst"],"LiquidBounce":[f"{mc}\\LiquidBounce-1.8"],"Rise":[f"{mc}\\Rise"],"FDP":[f"{ad}\\FDP-Client"],"Vape":[f"{ad}\\Vape"],"Sigma":[f"{ad}\\Sigma"],"Phobos":[f"{ad}\\Phobos"],"Impact":[f"{mc}\\Impact"]}
        for name,paths in clients.items():
            for p in paths:
                try:
                    if os.path.exists(p):self.report("CheatClients","CRITICAL",f"Cheat client: {name}",p)
                except Exception as client_error:
                    print(f"[DEBUG] scan_clients error for {name}: {type(client_error).__name__}")
    
    def scan_logs(self):
        lp=f"{self.path}\\AppData\\Roaming\\.minecraft\\logs\\latest.log"
        if not os.path.exists(lp):return
        try:
            with open(lp,"r",encoding="utf-8",errors="ignore") as f:
                content=f.read()
            for cmd in [".config",".bind",".panic",".toggle",".module",".cmd"]:
                if cmd in content:self.report("Logs","HIGH",f"Cheat command: {cmd}","")
            for mod in ["KillAura","Velocity","AutoClicker","ESP","Fly","NoFall","BadPackets","Speed"]:
                if mod in content:self.report("Logs","HIGH",f"Cheat module: {mod}","")
        except Exception as log_error:
            print(f"[DEBUG] scan_logs error: {type(log_error).__name__}: {log_error}")
    
    def scan_registry(self):
        try:
            rp=r"Software\Microsoft\Windows\CurrentVersion\Run"
            reg=winreg.ConnectRegistry(None,winreg.HKEY_CURRENT_USER)
            key=winreg.OpenKey(reg,rp)
            idx=0
            while True:
                try:
                    name,value,type_=winreg.EnumValue(key,idx)
                    if "%TEMP%" in value or "%APPDATA%" in value:
                        if len(Path(value).stem)>8:self.report("Registry","HIGH",f"Suspicious Run entry: {name}",value)
                    idx+=1
                except OSError:break
            winreg.CloseKey(key)
        except Exception as reg_error:
            print(f"[DEBUG] scan_registry error: {type(reg_error).__name__}")
    
    def scan_defender(self):
        try:
            rp=r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            reg=winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)
            key=winreg.OpenKey(reg,rp)
            idx=0
            while True:
                try:
                    name,value,type_=winreg.EnumValue(key,idx)
                    if any(s in name.lower() or s in value.lower() for s in [".minecraft","FDP","Vape","Sigma","hack"]):
                        self.report("Defender","HIGH",f"Exclusion: {name}",value)
                    idx+=1
                except OSError:break
            winreg.CloseKey(key)
        except Exception as defender_error:
            print(f"[DEBUG] scan_defender error: {type(defender_error).__name__}")
    
    def scan_temp(self):
        tp=os.getenv("TEMP")
        patterns=[r"^[a-zA-Z0-9]{6,12}\.dll$",r"java.*\.dll",r"thanatos.*\.dll"]
        try:
            for file in os.listdir(tp):
                if file.lower().endswith(".dll"):
                    for p in patterns:
                        if re.match(p,file,re.IGNORECASE):self.report("Temp","HIGH",f"Suspicious DLL: {file}",os.path.join(tp,file));break
        except Exception as temp_error:
            print(f"[DEBUG] scan_temp error: {type(temp_error).__name__}")
    
    def scan_java_injection(self):
        """Сканирование Java на подозрительные DLL инъекции"""
        try:
            r=subprocess.run(["tasklist","/M"],capture_output=True,text=True,timeout=10)
            lines=r.stdout.split("\n")
            java_mode=False
            # Только явные вредоносные DLL (без системных прокси)
            suspicious_dlls=["thanatos","misdirection"]
            # Стандартные Windows DLL которые загружаются в Java
            whitelist_dlls=["XblAuthManagerProxy","GameBarPresenceWriter","OneCoreUAPCommonProxyStub","OneCoreCommonProxyStub","usermgrproxy","ShellCommonCommonProxyStub","bcastdvr","execmodelproxy","OpenConsoleProxy","Microsoft.Extensions.DependencyInjection"]
            
            for line in lines:
                if "javaw.exe" in line or "java.exe" in line:
                    java_mode=True
                elif java_mode and line.strip() and "==" not in line:
                    # Очищаем имя от спецсимволов
                    dll_name=line.strip().split()[0] if line.strip().split() else ""
                    dll_name_clean=dll_name.replace(",","").replace(".","_").lower()
                    
                    # Проверяем только явно вредоносные
                    is_suspicious=any(s in dll_name_clean for s in suspicious_dlls)
                    is_whitelisted=any(w.lower() in dll_name_clean for w in whitelist_dlls)
                    
                    if is_suspicious and not is_whitelisted:
                        self.report("Java","HIGH",f"Suspicious DLL loaded in Java: {dll_name}","")
                elif "==" in line:
                    java_mode=False
        except Exception as java_error:
            print(f"[DEBUG] scan_java_injection error: {type(java_error).__name__}")
    
    def execute(self):
        print("\n"+"="*70)
        print("MINECRAFT CHEAT & MALWARE SCANNER v2.3 [SECURED]")
        print("="*70+"\n")
        
        try:
            self.scan_mods()
            self.scan_clients()
            self.scan_logs()
            self.scan_registry()
            self.scan_defender()
            self.scan_temp()
            self.scan_java_injection()
            self.display_results()
            self.save_log()
        except Exception as e:
            logger.error(f"Critical error during scanning: {e}")
            print(f"[ERROR] Scan interrupted: {e}")
    
    def display_results(self):
        print("\n"+"="*70)
        print("RESULTS")
        print("="*70+"\n")
        if not self.findings:print("✓ No threats detected!\n")
        else:
            for cat,items in self.findings.items():
                print(f"[{cat}] - {len(items)} findings")
                print("-"*70)
                for it in items:
                    print(f"{it['severity']:10} | {it['message']}")
                    if it["details"]:print(f"           | {it['details']}")
        print("\n"+"="*70)
        print(f"CRITICAL: {self.stats['CRITICAL']} | HIGH: {self.stats['HIGH']} | MEDIUM: {self.stats['MEDIUM']} | LOW: {self.stats['LOW']}")
        if self.stats["CRITICAL"]>0:print("\n⛔ CRITICAL THREATS DETECTED!")
        elif self.stats["HIGH"]>0:print("\n🔴 High-severity issues found.")
        else:print("\n✓ No critical threats.\n")
        
        # Информация для пользователя
        # пользовательские информационные строки удалены по просьбе
    
    def save_log(self):
        try:
            # Логирование ТОЛЬКО в памяти (для дебага)
            # removed noisy completed timestamp from console per user request
            logger.info(f"Total findings: {sum(self.stats.values())}")
            logger.info(f"Results: CRITICAL={self.stats['CRITICAL']} HIGH={self.stats['HIGH']} MEDIUM={self.stats['MEDIUM']} LOW={self.stats['LOW']}")
            
            # ВСЕ результаты видны в консоли выше
            # Файлы НЕ сохраняются на рабочий стол
            
        except Exception as log_error:
            logger.error(f"Log processing error: {type(log_error).__name__}: {log_error}")

if __name__=="__main__":
    s=MalwareDetector()
    s.execute()
    input("\nPress Enter to exit...")
