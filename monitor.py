"""
Module giám sát file hệ thống
"""
import os
import time
import hashlib
from datetime import datetime
from threading import Thread, Event
from config import MONITOR_INTERVAL

class FileMonitor:
    """Giám sát thay đổi file hệ thống"""
    
    def __init__(self):
        self.monitoring = False
        self.stop_event = Event()
        self.monitored_files = {}
        self.alerts = []
        self.scanner = None
        self.monitoring_thread = None
    
    def add_monitored_file(self, file_path):
        """Thêm file vào danh sách giám sát"""
        try:
            if os.path.exists(file_path):
                file_hash = self._calculate_hash(file_path)
                self.monitored_files[file_path] = {
                    "hash": file_hash,
                    "size": os.path.getsize(file_path),
                    "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                    "created": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                }
                return True
            return False
        except Exception as e:
            print(f"Lỗi khi thêm file giám sát: {e}")
            return False
    
    def remove_monitored_file(self, file_path):
        """Xóa file khỏi danh sách giám sát"""
        if file_path in self.monitored_files:
            del self.monitored_files[file_path]
            return True
        return False
    
    def get_monitored_files(self):
        """Lấy danh sách file đang giám sát"""
        return self.monitored_files
    
    def _calculate_hash(self, file_path):
        """Tính hash của file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None
    
    def _check_file_integrity(self, file_path):
        """Kiểm tra tính toàn vẹn của file"""
        if file_path not in self.monitored_files:
            return None
        
        current_info = {
            "hash": self._calculate_hash(file_path),
            "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat() if os.path.exists(file_path) else None
        }
        
        original_info = self.monitored_files[file_path]
        
        # Kiểm tra xem file có tồn tại không
        if not os.path.exists(file_path):
            alert = {
                "type": "file_deleted",
                "file": file_path,
                "timestamp": datetime.now().isoformat()
            }
            self.alerts.append(alert)
            return alert
        
        # Kiểm tra hash
        if current_info["hash"] != original_info["hash"]:
            alert = {
                "type": "file_modified",
                "file": file_path,
                "old_hash": original_info["hash"],
                "new_hash": current_info["hash"],
                "timestamp": datetime.now().isoformat()
            }
            self.alerts.append(alert)
            return alert
        
        return None
    
    def start_monitoring(self, files_to_monitor=None):
        """Bắt đầu giám sát"""
        if files_to_monitor:
            for file_path in files_to_monitor:
                self.add_monitored_file(file_path)
        
        self.monitoring = True
        self.stop_event.clear()
        
        def monitoring_loop():
            while not self.stop_event.is_set():
                if self.monitored_files:
                    for file_path in list(self.monitored_files.keys()):
                        try:
                            self._check_file_integrity(file_path)
                        except:
                            pass
                
                time.sleep(MONITOR_INTERVAL)
        
        self.monitoring_thread = Thread(target=monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Dừng giám sát"""
        self.monitoring = False
        self.stop_event.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
    
    def get_alerts(self):
        """Lấy danh sách cảnh báo"""
        return self.alerts
    
    def clear_alerts(self):
        """Xóa danh sách cảnh báo"""
        self.alerts = []
    
    def get_system_files_to_monitor(self):
        """Lấy danh sách file hệ thống quan trọng để giám sát"""
        system_files = []
        
        # Các file quan trọng trên Windows
        critical_paths = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SECURITY",
            "C:\\Windows\\System32\\config\\SOFTWARE",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        for path in critical_paths:
            if os.path.exists(path):
                system_files.append(path)
        
        return system_files


class RealTimeProtection:
    """Bảo vệ thời gian thực"""
    
    def __init__(self):
        self.file_monitor = FileMonitor()
        self.scanner = None
        self.protected_paths = []
        self.enabled = False
    
    def enable_protection(self, paths=None):
        """Bật bảo vệ thời gian thực"""
        if paths:
            self.protected_paths = paths
        else:
            # Bảo vệ các thư mục quan trọng
            self.protected_paths = [
                os.path.expanduser("~"),
                "C:\\Windows\\Temp",
                "C:\\Users\\Public"
            ]
        
        # Bắt đầu giám sát
        files_to_monitor = self.file_monitor.get_system_files_to_monitor()
        self.file_monitor.start_monitoring(files_to_monitor)
        
        self.enabled = True
    
    def disable_protection(self):
        """Tắt bảo vệ thời gian thực"""
        self.file_monitor.stop_monitoring()
        self.enabled = False
    
    def check_new_file(self, file_path):
        """Kiểm tra file mới được tạo"""
        if not self.enabled:
            return None
        
        # Quét file mới
        if self.scanner:
            result = self.scanner.scan_file(file_path)
            return result
        
        return None
    
    def get_status(self):
        """Lấy trạng thái bảo vệ"""
        return {
            "enabled": self.enabled,
            "protected_paths": self.protected_paths,
            "monitoring_files": len(self.file_monitor.monitored_files),
            "alerts_count": len(self.file_monitor.alerts),
            "timestamp": datetime.now().isoformat()
        }


def start_real_time_protection(paths=None):
    """Khởi động bảo vệ thời gian thực"""
    protection = RealTimeProtection()
    protection.enable_protection(paths)
    return protection
