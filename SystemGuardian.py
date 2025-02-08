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
import psutil
import threading
from datetime import datetime, timedelta
import queue
import json
import subprocess
import re
from win10toast import ToastNotifier
import logging

# Constants
CONFIG_PATH = Path("C:/ProgramData/ComponentMonitor/config")
LOG_PATH = Path("C:/ProgramData/ComponentMonitor/logs")
QUARANTINE_PATH = Path("C:/ProgramData/ComponentMonitor/quarantine")
DRIVER_STORE_PATH = Path("C:/Windows/System32/DriverStore/FileRepository")

class SystemGuardianService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SystemGuardian"
    _svc_display_name_ = "System Component Guardian"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.event_queue = queue.Queue()
        self.registry_queue = queue.Queue()
        self.isolation_queue = queue.PriorityQueue()
        self.retry_registry = {}
        self.component_dependencies = {}
        self.driver_map = {}
        self.toaster = ToastNotifier()
        
        # Initialize directories
        self.init_directories()
        
        # Setup logging
        self.setup_logging()
        
        # Load configuration
        self.load_configurations()

    def init_directories(self):
        CONFIG_PATH.mkdir(parents=True, exist_ok=True)
        LOG_PATH.mkdir(parents=True, exist_ok=True)
        QUARANTINE_PATH.mkdir(parents=True, exist_ok=True)

    def setup_logging(self):
        logging.basicConfig(
            filename=LOG_PATH / "guardian.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_PATH / "guardian.log"),
                logging.StreamHandler()
            ]
        )

    def load_configurations(self):
        # Load event patterns
        self.event_patterns = self.load_json_config('event_patterns.json', {
            'warnings': {
                'sources': ['Service Control Manager', 'Disk', 'Netwtw14'],
                'event_ids': [1001, 6062, 219]
            },
            'errors': {
                'sources': ['DCOM', 'DriverFrameworks-UserMode', 'Service Control Manager'],
                'event_ids': [10005, 10010, 7000, 7009]
            }
        })

        # Load component dependencies
        self.component_dependencies = self.load_json_config('dependencies.json', {})

        # Load driver registry map
        self.driver_map = self.load_json_config('driver_map.json', {})

    def load_json_config(self, filename, default):
        config_file = CONFIG_PATH / filename
        if config_file.exists():
            with open(config_file) as f:
                return json.load(f)
        return default

    def monitor_event_logs(self):
        """Continuous monitoring of system event logs"""
        while self.is_running:
            try:
                hand = win32evtlog.OpenEventLog(None, 'System')
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    if self.is_relevant_event(event):
                        event_data = self.process_event(event)
                        self.event_queue.put(event_data)
                
                win32evtlog.CloseEventLog(hand)
                win32event.WaitForSingleObject(self.hWaitStop, 5000)
                
            except Exception as e:
                logging.error(f"Event log monitoring failed: {str(e)}")
                win32event.WaitForSingleObject(self.hWaitStop, 10000)

    def is_relevant_event(self, event):
        """Determine if event matches configured patterns"""
        source = event.SourceName
        event_id = event.EventID
        event_type = event.EventType
        
        if event_type == win32evtlog.EVENTLOG_WARNING_TYPE:
            return (source in self.event_patterns['warnings']['sources'] or
                    event_id in self.event_patterns['warnings']['event_ids'])
        
        elif event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            return (source in self.event_patterns['errors']['sources'] or
                    event_id in self.event_patterns['errors']['event_ids'])
        
        return False

    def process_event(self, event):
        """Extract critical information from events"""
        message = win32evtlogutil.SafeFormatMessage(event, 'System')
        return {
            'timestamp': event.TimeGenerated,
            'source': event.SourceName,
            'event_id': event.EventID,
            'event_type': event.EventType,
            'message': message,
            'component': self.extract_component(message),
            'category': self.classify_event(event, message)
        }

    def extract_component(self, message):
        """Extract component name from event message"""
        patterns = {
            'service': r'service\s+(?:\"(.+?)\")',
            'driver': r'driver\s+(?:\"(.+?)\")',
            'dcom': r'CLSID\s+\{([A-F0-9-]+)\}'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return f"{key}:{match.group(1)}"
        return "unknown"

    def classify_event(self, event, message):
        """Classify event severity and type"""
        if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
            if any(err in message for err in ['DCOM', 'CLSID']):
                return 'critical_com'
            if 'driver' in message.lower():
                return 'critical_driver'
            return 'system_error'
        
        return 'service_warning' if 'service' in message.lower() else 'hardware_warning'

    def process_events(self):
        """Process queued events with appropriate actions"""
        while self.is_running:
            try:
                event = self.event_queue.get(timeout=1)
                logging.info(f"Processing event: {event['component']} - {event['category']}")

                if event['event_type'] == win32evtlog.EVENTLOG_WARNING_TYPE:
                    self.handle_warning(event)
                else:
                    self.handle_error(event)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Event processing error: {str(e)}")

    def handle_warning(self, event):
        """Handle warning events with retry logic"""
        component = event['component']
        current_time = datetime.now()
        
        # Update retry registry
        if component not in self.retry_registry:
            self.retry_registry[component] = {
                'count': 0,
                'last_attempt': current_time
            }
        else:
            # Reset if last attempt was over 1 hour ago
            if (current_time - self.retry_registry[component]['last_attempt']) > timedelta(hours=1):
                self.retry_registry[component] = {
                    'count': 0,
                    'last_attempt': current_time
                }

        if self.retry_registry[component]['count'] < 3:
            if self.attempt_repair(component):
                logging.info(f"Successfully repaired {component}")
                return
            self.retry_registry[component]['count'] += 1
            self.retry_registry[component]['last_attempt'] = current_time
        else:
            self.isolation_queue.put((
                1,  # Medium priority
                {
                    'component': component,
                    'reason': f"Max retries exceeded for warnings: {event['message']}",
                    'action': 'isolate'
                }
            ))

    def handle_error(self, event):
        """Immediate isolation for error events"""
        component = event['component']
        affected_components = self.get_affected_components(component)
        
        for comp in affected_components:
            self.isolation_queue.put((
                0,  # Highest priority
                {
                    'component': comp,
                    'reason': f"Cascading error from {component}: {event['message']}",
                    'action': 'isolate'
                }
            ))

    def get_affected_components(self, component):
        """Get components with dependency relationships"""
        affected = set()
        queue = [component]
        
        while queue:
            current = queue.pop(0)
            affected.add(current)
            # Get both dependencies and dependents
            queue.extend([
                dep for dep in 
                self.component_dependencies.get(current, []) 
                if dep not in affected
            ])
        
        return affected

    def attempt_repair(self, component):
        """Attempt automatic repair of component"""
        try:
            if component.startswith('service:'):
                return self.repair_service(component.split(':')[1])
            elif component.startswith('driver:'):
                return self.repair_driver(component.split(':')[1])
            elif component.startswith('dcom:'):
                return self.repair_dcom(component.split(':')[1])
            return False
        except Exception as e:
            logging.error(f"Repair attempt failed for {component}: {str(e)}")
            return False

    def repair_service(self, service_name):
        """Repair service through restart and dependency check"""
        try:
            win32serviceutil.RestartService(service_name)
            self.validate_service_registry(service_name)
            return True
        except Exception as e:
            logging.error(f"Service repair failed for {service_name}: {str(e)}")
            return False

    def repair_driver(self, driver_name):
        """Repair driver through reinstallation"""
        try:
            # Check driver store for backup
            driver_path = self.find_driver_in_store(driver_name)
            if driver_path:
                subprocess.run([
                    'pnputil', '/add-driver', str(driver_path), 
                    '/install', '/force'
                ], check=True)
                return True
            return False
        except Exception as e:
            logging.error(f"Driver repair failed for {driver_name}: {str(e)}")
            return False

    def repair_dcom(self, clsid):
        """Repair DCOM registration and permissions"""
        try:
            self.secure_registry_key(f"CLSID\\{clsid}")
            subprocess.run([
                'regsvr32', '/s', '/i', f"{clsid}.dll"
            ], check=True)
            return True
        except Exception as e:
            logging.error(f"DCOM repair failed for {clsid}: {str(e)}")
            return False

    def validate_service_registry(self, service_name):
        """Validate service registry entries"""
        try:
            key_path = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                image_path = winreg.QueryValueEx(key, 'ImagePath')[0]
                if not Path(image_path.strip('"')).exists():
                    self.registry_queue.put({
                        'type': 'missing_binary',
                        'service': service_name,
                        'path': image_path
                    })
        except Exception as e:
            logging.error(f"Registry validation failed for {service_name}: {str(e)}")

    def monitor_registry(self):
        """Continuous registry health monitoring"""
        while self.is_running:
            try:
                self.scan_service_registry()
                self.scan_driver_registry()
                win32event.WaitForSingleObject(self.hWaitStop, 30000)
            except Exception as e:
                logging.error(f"Registry monitoring failed: {str(e)}")

    def scan_service_registry(self):
        """Scan service registry entries for issues"""
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                          r"SYSTEM\CurrentControlSet\Services") as services_key:
            i = 0
            while True:
                try:
                    service_name = winreg.EnumKey(services_key, i)
                    self.validate_service_registry(service_name)
                    i += 1
                except WindowsError:
                    break

    def scan_driver_registry(self):
        """Scan driver registry entries for inconsistencies"""
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                          r"SYSTEM\CurrentControlSet\Control\Class") as class_key:
            i = 0
            while True:
                try:
                    class_guid = winreg.EnumKey(class_key, i)
                    self.check_driver_class(class_guid)
                    i += 1
                except WindowsError:
                    break

    def check_driver_class(self, class_guid):
        """Check individual driver class entries"""
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                          f"SYSTEM\\CurrentControlSet\\Control\\Class\\{class_guid}") as guid_key:
            try:
                driver_desc = winreg.QueryValueEx(guid_key, 'DriverDesc')[0]
                service_name = winreg.QueryValueEx(guid_key, 'Service')[0]
                image_path = self.get_driver_image_path(service_name)
                
                if not Path(image_path).exists():
                    self.registry_queue.put({
                        'type': 'driver_missing',
                        'service': service_name,
                        'path': image_path,
                        'guid': class_guid
                    })
                    
            except WindowsError:
                pass

    def get_driver_image_path(self, service_name):
        """Get driver image path from service registry entry"""
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                          f"SYSTEM\\CurrentControlSet\\Services\\{service_name}") as service_key:
            return winreg.QueryValueEx(service_key, 'ImagePath')[0]

    def process_registry_issues(self):
        """Handle detected registry issues"""
        while self.is_running:
            try:
                issue = self.registry_queue.get(timeout=1)
                if issue['type'] == 'missing_binary':
                    self.handle_missing_binary(issue)
                elif issue['type'] == 'driver_missing':
                    self.handle_missing_driver(issue)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Registry issue processing failed: {str(e)}")

    def handle_missing_binary(self, issue):
        """Handle missing service binaries"""
        service_name = issue['service']
        self.notify_user(
            "Critical System Issue",
            f"Service binary missing for {service_name}"
        )
        
        self.isolation_queue.put((
            0,
            {
                'component': f"service:{service_name}",
                'reason': f"Missing binary: {issue['path']}",
                'action': 'isolate'
            }
        ))

    def handle_missing_driver(self, issue):
        """Handle missing driver files"""
        self.notify_user(
            "Driver Corruption Detected",
            f"Missing driver file: {issue['path']}"
        )
        
        try:
            self.quarantine_driver(issue['service'])
            self.isolation_queue.put((
                0,
                {
                    'component': f"driver:{issue['service']}",
                    'reason': f"Missing driver: {issue['path']}",
                    'action': 'reinstall'
                }
            ))
        except Exception as e:
            logging.error(f"Driver quarantine failed: {str(e)}")

    def quarantine_driver(self, service_name):
        """Move problematic driver to quarantine"""
        driver_path = self.get_driver_image_path(service_name)
        if Path(driver_path).exists():
            subprocess.run([
                'takeown', '/f', driver_path
            ], check=True)
            
            subprocess.run([
                'icacls', driver_path, '/grant', 'Administrators:F'
            ], check=True)
            
            target_path = QUARANTINE_PATH / Path(driver_path).name
            Path(driver_path).rename(target_path)

    def process_isolation_queue(self):
        """Process components needing isolation"""
        while self.is_running:
            try:
                priority, item = self.isolation_queue.get(timeout=1)
                component = item['component']
                logging.warning(f"Isolating component: {component}")
                
                if component.startswith('service:'):
                    self.isolate_service(component.split(':')[1])
                elif component.startswith('driver:'):
                    self.isolate_driver(component.split(':')[1])
                elif component.startswith('dcom:'):
                    self.isolate_dcom(component.split(':')[1])
                
                self.notify_user(
                    "System Component Isolation",
                    f"Component isolated: {component}"
                )
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Isolation failed: {str(e)}")

    def isolate_service(self, service_name):
        """Isolate problematic service"""
        try:
            win32serviceutil.StopService(service_name)
            subprocess.run([
                'sc', 'config', service_name, 'start=', 'disabled'
            ], check=True)
            
            # Backup service registry entry
            self.backup_registry_key(
                f"SYSTEM\\CurrentControlSet\\Services\\{service_name}",
                f"service_{service_name}.reg"
            )
            
        except Exception as e:
            logging.error(f"Service isolation failed for {service_name}: {str(e)}")

    def isolate_driver(self, driver_name):
        """Isolate problematic driver"""
        try:
            subprocess.run([
                'pnputil', '/delete-driver', driver_name, '/force'
            ], check=True)
            
            # Remove from driver store
            driver_store = DRIVER_STORE_PATH / driver_name
            if driver_store.exists():
                subprocess.run([
                    'rmdir', '/s', '/q', str(driver_store)
                ], check=True)
                
        except Exception as e:
            logging.error(f"Driver isolation failed for {driver_name}: {str(e)}")

    def isolate_dcom(self, clsid):
        """Isolate problematic DCOM component"""
        try:
            self.secure_registry_key(f"CLSID\\{clsid}")
            subprocess.run([
                'reg', 'delete',
                f"HKLM\\SOFTWARE\\Classes\\CLSID\\{clsid}", '/f'
            ], check=True)
        except Exception as e:
            logging.error(f"DCOM isolation failed for {clsid}: {str(e)}")

    def backup_registry_key(self, key_path, filename):
        """Backup registry key before modification"""
        backup_file = CONFIG_PATH / 'backups' / filename
        subprocess.run([
            'reg', 'export',
            f"HKLM\\{key_path}",
            str(backup_file), '/y'
        ], check=True)

    def secure_registry_key(self, key_path):
        """Take ownership and secure registry key"""
        try:
            subprocess.run([
                'takeown', '/f', f"HKLM\\{key_path}", '/r', '/d', 'y'
            ], check=True)
            
            subprocess.run([
                'icacls', f"HKLM\\{key_path}", '/inheritance:r',
                '/grant:r', 'Administrators:(F)', '/t', '/c', '/l', '/q'
            ], check=True)
        except Exception as e:
            logging.error(f"Registry security failed for {key_path}: {str(e)}")

    def notify_user(self, title, message):
        """Send user notification via toast"""
        try:
            self.toaster.show_toast(
                title,
                message,
                duration=10,
                threaded=True
            )
        except Exception as e:
            logging.error(f"User notification failed: {str(e)}")

    def SvcStop(self):
        """Stop the service"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        """Main service entry point"""
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        logging.info("System Guardian service started")
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_event_logs),
            threading.Thread(target=self.monitor_registry),
            threading.Thread(target=self.process_events),
            threading.Thread(target=self.process_registry_issues),
            threading.Thread(target=self.process_isolation_queue)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Main service loop
        while self.is_running:
            win32event.WaitForSingleObject(self.hWaitStop, 1000)
        
        logging.info("System Guardian service stopped")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SystemGuardianService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SystemGuardianService)