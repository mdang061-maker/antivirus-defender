"""
Module quản lý danh sách đen và trắng
"""
import os
from datetime import datetime
from database import MalwareDatabase, calculate_file_hash

class ThreatManager:
    """Quản lý các mối đe dọa an ninh"""
    
    def __init__(self):
        self.malware_db = MalwareDatabase()
        self.threat_logs = []
    
    def block_file(self, file_path, reason=""):
        """Chặn một file"""
        try:
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                self.malware_db.add_to_blacklist(file_hash, reason)
                return {
                    "status": "success",
                    "file": file_path,
                    "hash": file_hash,
                    "action": "blocked",
                    "timestamp": datetime.now().isoformat()
                }
            return {"status": "error", "message": "Không thể tính hash của file"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def unblock_file(self, file_hash):
        """Bỏ chặn một file"""
        try:
            self.malware_db.remove_from_blacklist(file_hash)
            return {
                "status": "success",
                "hash": file_hash,
                "action": "unblocked",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def whitelist_file(self, file_path, reason=""):
        """Cho phép một file (thêm vào danh sách trắng)"""
        try:
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                self.malware_db.add_to_whitelist(file_hash, reason)
                return {
                    "status": "success",
                    "file": file_path,
                    "hash": file_hash,
                    "action": "whitelisted",
                    "timestamp": datetime.now().isoformat()
                }
            return {"status": "error", "message": "Không thể tính hash của file"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def unwhitelist_file(self, file_hash):
        """Xóa file khỏi danh sách trắng"""
        try:
            self.malware_db.remove_from_whitelist(file_hash)
            return {
                "status": "success",
                "hash": file_hash,
                "action": "unwhitelisted",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def get_blacklist(self):
        """Lấy danh sách đen"""
        return self.malware_db.blacklist
    
    def get_whitelist(self):
        """Lấy danh sách trắng"""
        return self.malware_db.whitelist
    
    def is_file_blocked(self, file_path):
        """Kiểm tra xem file có bị chặn không"""
        try:
            file_hash = calculate_file_hash(file_path)
            return self.malware_db.is_blacklisted(file_hash) if file_hash else False
        except:
            return False
    
    def log_threat(self, threat_info):
        """Ghi lại thông tin mối đe dọa"""
        threat_log = {
            **threat_info,
            "timestamp": datetime.now().isoformat()
        }
        self.threat_logs.append(threat_log)
        
        #Limit logs
        if len(self.threat_logs) > 1000:
            self.threat_logs = self.threat_logs[-500:]
    
    def get_threat_logs(self, limit=50):
        """Lấy lịch sử mối đe dọa"""
        return self.threat_logs[-limit:]
    
    def clear_threat_logs(self):
        """Xóa lịch sử mối đe dọa"""
        self.threat_logs = []


class FileActionHandler:
    """Xử lý hành động với file"""
    
    def __init__(self):
        self.quarantine_manager = None
    
    def set_quarantine_manager(self, manager):
        """Thiết lập quản lý quarantine"""
        self.quarantine_manager = manager
    
    def quarantine_file(self, file_path):
        """Cách ly file"""
        if self.quarantine_manager:
            return self.quarantine_manager.quarantine_file(file_path)
        return False
    
    def delete_file(self, file_path):
        """Xóa file"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception as e:
            print(f"Lỗi khi xóa file: {e}")
            return False
    
    def restore_file(self, quarantined_name, original_path):
        """Khôi phục file từ quarantine"""
        if self.quarantine_manager:
            return self.quarantine_manager.restore_file(quarantined_name, original_path)
        return False
    
    def export_blacklist(self, output_file):
        """Xuất danh sách đen ra file"""
        try:
            blacklist = self.malware_db.blacklist if hasattr(self, 'malware_db') else []
            with open(output_file, 'w', encoding='utf-8') as f:
                for item in blacklist:
                    f.write(f"{item['hash']},{item.get('reason', 'N/A')},{item.get('added_date', 'N/A')}\n")
            return {"status": "success", "file": output_file}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def import_blacklist(self, input_file):
        """Nhập danh sách đen từ file"""
        try:
            imported = 0
            with open(input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 1:
                        file_hash = parts[0]
                        reason = parts[1] if len(parts) > 1 else "Imported"
                        self.malware_db.add_to_blacklist(file_hash, reason)
                        imported += 1
            return {"status": "success", "imported": imported}
        except Exception as e:
            return {"status": "error", "message": str(e)}


def create_threat_manager():
    """Tạo một đối tượng ThreatManager"""
    return ThreatManager()
