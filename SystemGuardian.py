import win32serviceutil
import win32service
import win32event
import servicemanager
import win32api
import win32evtlog
import win32evtlogutil
import win32security
import win32con
import winreg
from pathlib import Path
import sys
import psutil
import threading
from datetime import datetime
import queue
import subprocess
import re
from win10toast import ToastNotifier
import logging
import time
import pickle
import wmi
import json
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import os
from contextlib import contextmanager
import sqlite3

# Enhanced Configuration
class Config:
    BASE_DIR = Path("C:/ProgramData/SystemGuardian")
    LOG_DIR = BASE_DIR / "logs"
    BACKUP_DIR = BASE_DIR / "backups"
    RECOVERY_DIR = BASE_DIR / "recovery_points"
    QUARANTINE_DIR = BASE_DIR / "quarantine"
    DB_PATH = BASE_DIR / "guardian.db"
    
    # Maximum limits
    MAX_QUEUE_SIZE = 1000
    MAX_THREADS = 4
    MAX_RECOVERY_POINTS = 5
    MAX_BACKUP_AGE_DAYS = 7
    
    # Monitoring intervals (seconds)
    EVENT_CHECK_INTERVAL = 5
    CACHE_UPDATE_INTERVAL = 3600
    BACKUP_INTERVAL = 86400  # 24 hours
    
    # Critical paths to monitor
    CRITICAL_REG_PATHS = [
        r"SYSTEM\CurrentControlSet\Services",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
        r"SYSTEM\CurrentControlSet\Control\Class"
    ]
    
    # System paths
    DRIVER_STORE = Path("C:/Windows/System32/DriverStore/FileRepository")
    SYSTEM32_DRIVERS = Path("C:/Windows/System32/drivers")

@dataclass
class SystemComponent:
    name: str
    type: str
    path: str
    dependencies: List[str]
    hash: str
    last_modified: float
    status: str

@dataclass
class RecoveryPoint:
    timestamp: float
    components: Dict[str, SystemComponent]
    registry_backup: str
    description: str

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        with self.get_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS components (
                    name TEXT PRIMARY KEY,
                    type TEXT,
                    path TEXT,
                    dependencies TEXT,
                    hash TEXT,
                    last_modified REAL,
                    status TEXT
                );
                
                CREATE TABLE IF NOT EXISTS recovery_points (
                    timestamp REAL PRIMARY KEY,
                    components TEXT,
                    registry_backup TEXT,
                    description TEXT
                );
                
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    timestamp REAL,
                    type TEXT,
                    component TEXT,
                    description TEXT,
                    severity TEXT
                );
            ''')
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

class SystemGuardianService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SystemGuardian"
    _svc_display_name_ = "System Stability Guardian"
    _svc_description_ = "Monitors and protects critical system components with recovery capabilities"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.event_queue = queue.Queue(maxsize=Config.MAX_QUEUE_SIZE)
        self.component_lock = threading.Lock()
        self.wmi_connection = None
        self.thread_pool = None
        self.db = None
        self.components = {}
        self.toaster = ToastNotifier()
        
        # Initialize environment
        self.initialize_environment()

    def initialize_environment(self):
        """Initialize service environment with error handling"""
        try:
            # Create required directories
            for directory in [Config.BASE_DIR, Config.LOG_DIR, Config.BACKUP_DIR,
                            Config.RECOVERY_DIR, Config.QUARANTINE_DIR]:
                directory.mkdir(parents=True, exist_ok=True)
            
            # Setup logging
            self.setup_logging()
            
            # Initialize database
            self.db = DatabaseManager(Config.DB_PATH)
            
            # Initialize WMI connection
            self.wmi_connection = wmi.WMI()
            
            # Initialize thread pool
            self.thread_pool = ThreadPoolExecutor(max_workers=Config.MAX_THREADS)
            
            logging.info("Environment initialized successfully")
        
        except Exception as e:
            logging.critical(f"Failed to initialize environment: {str(e)}")
            raise

    def setup_logging(self):
        """Configure logging with rotation"""
        log_file = Config.LOG_DIR / f"guardian_{datetime.now().strftime('%Y%m%d')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.RotatingFileHandler(
                    log_file,
                    maxBytes=10485760,  # 10MB
                    backupCount=5
                ),
                logging.StreamHandler()
            ]
        )

    def create_recovery_point(self, description: str = "Automatic recovery point"):
        """Create system recovery point"""
        try:
            timestamp = time.time()
            
            # Backup registry
            reg_backup_path = Config.BACKUP_DIR / f"registry_backup_{timestamp}.reg"
            self.backup_registry(reg_backup_path)
            
            # Create recovery point
            recovery_point = RecoveryPoint(
                timestamp=timestamp,
                components=self.components.copy(),
                registry_backup=str(reg_backup_path),
                description=description
            )
            
            # Store in database
            with self.db.get_connection() as conn:
                conn.execute(
                    "INSERT INTO recovery_points VALUES (?, ?, ?, ?)",
                    (recovery_point.timestamp, json.dumps(recovery_point.components),
                     recovery_point.registry_backup, recovery_point.description)
                )
            
            # Cleanup old recovery points
            self.cleanup_recovery_points()
            
            logging.info(f"Created recovery point: {description}")
            return True
        
        except Exception as e:
            logging.error(f"Failed to create recovery point: {str(e)}")
            return False

    def restore_recovery_point(self, timestamp: float) -> bool:
        """Restore system to a previous recovery point"""
        try:
            with self.db.get_connection() as conn:
                result = conn.execute(
                    "SELECT * FROM recovery_points WHERE timestamp = ?",
                    (timestamp,)
                ).fetchone()
                
                if not result:
                    raise ValueError("Recovery point not found")
                
                # Restore registry
                self.restore_registry(Path(result[2]))
                
                # Restore components
                restored_components = json.loads(result[1])
                with self.component_lock:
                    self.components = restored_components
                
                logging.info(f"Restored system to recovery point: {result[3]}")
                return True
        
        except Exception as e:
            logging.error(f"Failed to restore recovery point: {str(e)}")
            return False

    @contextmanager
    def backup_registry(self, backup_path: Path):
        """Backup registry with context manager"""
        try:
            subprocess.run(
                ['reg', 'export', 'HKLM', str(backup_path), '/y'],
                check=True, capture_output=True
            )
            yield backup_path
        except Exception as e:
            logging.error(f"Registry backup failed: {str(e)}")
            raise
        finally:
            if not backup_path.exists():
                logging.warning(f"Registry backup not created: {backup_path}")

    def restore_registry(self, backup_path: Path):
        """Restore registry from backup"""
        if not backup_path.exists():
            raise FileNotFoundError(f"Registry backup not found: {backup_path}")
        
        try:
            subprocess.run(
                ['reg', 'import', str(backup_path)],
                check=True, capture_output=True
            )
            logging.info(f"Registry restored from: {backup_path}")
        except Exception as e:
            logging.error(f"Registry restore failed: {str(e)}")
            raise

    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logging.error(f"Failed to calculate hash for {file_path}: {str(e)}")
            return ""

    def verify_component(self, component: SystemComponent) -> bool:
        """Verify component integrity"""
        try:
            # Check existence
            path = Path(component.path)
            if not path.exists():
                return False
            
            # Verify hash
            current_hash = self.calculate_file_hash(path)
            if current_hash != component.hash:
                return False
            
            # Check dependencies
            for dep in component.dependencies:
                if dep not in self.components:
                    return False
            
            return True
        
        except Exception as e:
            logging.error(f"Component verification failed: {str(e)}")
            return False

    def monitor_system_events(self):
        """Enhanced event monitoring using WMI"""
        try:
            # Set up WMI event watcher
            watcher = self.wmi_connection.watch_for(
                notification_type="Creation",
                wmi_class="Win32_NTLogEvent",
                Type="Error OR Warning"
            )
            
            while self.is_running:
                event = watcher(timeout_ms=1000)
                if event:
                    self.process_wmi_event(event)
        
        except Exception as e:
            logging.error(f"Event monitoring failed: {str(e)}")
            time.sleep(Config.EVENT_CHECK_INTERVAL)

    def process_wmi_event(self, event):
        """Process WMI events"""
        try:
            entry = {
                'time': time.time(),
                'type': event.Type,
                'source': event.SourceName,
                'message': event.Message,
                'severity': 'critical' if event.Type == 'Error' else 'warning'
            }
            
            if self.event_queue.qsize() < Config.MAX_QUEUE_SIZE:
                self.event_queue.put(entry)
                self.thread_pool.submit(self.handle_event, entry)
            else:
                logging.warning("Event queue full, dropping event")
        
        except Exception as e:
            logging.error(f"WMI event processing failed: {str(e)}")

    def handle_event(self, event):
        """Enhanced event handling with recovery"""
        try:
            # Create recovery point before taking action
            if event['severity'] == 'critical':
                self.create_recovery_point(f"Pre-action recovery point for {event['source']}")
            
            component = self.identify_affected_component(event['message'])
            if component:
                if event['severity'] == 'critical':
                    self.isolate_component(component)
                else:
                    self.attempt_repair(component)
        
        except Exception as e:
            logging.error(f"Event handling failed: {str(e)}")

    def isolate_component(self, component: SystemComponent):
        """Isolate problematic component with backup"""
        try:
            # Backup before isolation
            backup_path = Config.BACKUP_DIR / f"{component.name}_{time.time()}"
            shutil.copy2(component.path, backup_path)
            
            # Perform isolation
            if component.type == 'driver':
                self.disable_driver(component)
            elif component.type == 'service':
                self.disable_service(component)
            
            # Update component status
            component.status = 'isolated'
            self.update_component(component)
            
            self.notify_user(
                "Component Isolated",
                f"Isolated {component.type}: {component.name}\nBackup created at: {backup_path}"
            )
        
        except Exception as e:
            logging.error(f"Component isolation failed: {str(e)}")
            raise

    def cleanup_recovery_points(self):
        """Clean up old recovery points"""
        try:
            with self.db.get_connection() as conn:
                # Keep only recent recovery points
                conn.execute(
                    "DELETE FROM recovery_points WHERE timestamp NOT IN "
                    "(SELECT timestamp FROM recovery_points ORDER BY timestamp DESC "
                    f"LIMIT {Config.MAX_RECOVERY_POINTS})"
                )
            
            # Clean up associated files
            for backup in Config.BACKUP_DIR.glob("registry_backup_*"):
                if (time.time() - float(backup.stem.split('_')[-1])) > \
                   (Config.MAX_BACKUP_AGE_DAYS * 86400):
                    backup.unlink()
        
        except Exception as e:
            logging.error(f"Recovery point cleanup failed: {str(e)}")

    def SvcStop(self):
        """Enhanced service stop"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_running = False
        self.thread_pool.shutdown(wait=True)
        win32event.SetEvent(self.stop_event)
        
        # Create final recovery point
        self.create_recovery_point("Service shutdown recovery point")

    def SvcDoRun(self):
        """Enhanced service run"""
        try:
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            
            # Create initial recovery point
            self.create_recovery_point("Service startup recovery point")
            
            # Start monitoring threads
            monitor_thread = threading.Thread(target=self.monitor_system_events)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Main service loop
            while self.is_running:
                result = win32event.WaitForSingleObject(self.stop_event, 1000)
                if result == win32event.WAIT_OBJECT_0:
                    break
            
            logging.info("Service stopped normally")
        
        except Exception as e:
            logging.critical(f"Service run failed: {str(e)}")
            self.SvcStop()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SystemGuardianService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SystemGuardianService)