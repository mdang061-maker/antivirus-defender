"""
Module quét file và phát hiện mã độc
"""
import os
import hashlib
from datetime import datetime
from config import SCAN_CHUNK_SIZE, MAX_FILE_SIZE
from database import calculate_file_hash, MalwareDatabase

class Scanner:
    """Module quét file và phát hiện mã độc"""
    
    def __init__(self):
        self.malware_db = MalwareDatabase()
        self.scan_results = []
        self.total_files_scanned = 0
        self.threats_found = 0
    
    def scan_file(self, file_path):
        """Quét một file để tìm mã độc"""
        result = {
            "file_path": file_path,
            "status": "clean",
            "threat_name": None,
            "threat_type": None,
            "hash": None,
            "timestamp": None
        }
        
        try:
            # Kiểm tra xem file có tồn tại không
            if not os.path.exists(file_path):
                result["status"] = "error"
                result["error"] = "File không tồn tại"
                return result
            
            # Kiểm tra kích thước file
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                result["status"] = "skipped"
                result["error"] = "File quá lớn (giới hạn 100MB)"
                return result
            
            # Tính hash của file
            file_hash = calculate_file_hash(file_path)
            if not file_hash:
                result["status"] = "error"
                result["error"] = "Không thể tính hash của file"
                return result
            
            result["hash"] = file_hash
            
            # Kiểm tra trong danh sách đen
            if self.malware_db.is_blacklisted(file_hash):
                result["status"] = "threat"
                result["threat_name"] = "Blacklisted File"
                result["threat_type"] = "Security Policy"
                self.threats_found += 1
                return result
            
            # Kiểm tra trong danh sách trắng (file an toàn)
            if self.malware_db.is_whitelisted(file_hash):
                result["status"] = "whitelisted"
                return result
            
            # Kiểm tra trong cơ sở dữ liệu mã độc
            if self.malware_db.is_malware(file_hash):
                malware_info = self.malware_db.get_malware_info(file_hash)
                result["status"] = "threat"
                result["threat_name"] = malware_info.get("name", "Unknown Malware")
                result["threat_type"] = malware_info.get("type", "Unknown")
                self.threats_found += 1
                return result
            
            # Quét nội dung file (phát hiện ký hiệu độc hại)
            if self._content_scan(file_path):
                result["status"] = "suspicious"
                result["threat_name"] = "Suspicious Content"
                result["threat_type"] = "Heuristic Detection"
                self.threats_found += 1
            
            return result
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            return result
    
    def _content_scan(self, file_path):
        """Quét nội dung file để tìm ký hiệu độc hại"""
        suspicious_patterns = [
            b'eval(', b'exec(', b'system(', b'cmd.exe', b'powershell',
            b'base64_decode', b'createobject', b'wscript', b'vbscript',
            b'/shell', b'/command', b'runas', b'set-executionpolicy',
            b'iex(', b'invoke-expression', b'invoke-webrequest'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Quét 1MB đầu tiên
                
                for pattern in suspicious_patterns:
                    if pattern.lower() in content.lower():
                        return True
            return False
        except:
            return False
    
    def scan_directory(self, directory_path, recursive=True):
        """Quét toàn bộ thư mục"""
        results = []
        self.total_files_scanned = 0
        self.threats_found = 0
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        result = self.scan_file(file_path)
                        result["timestamp"] = datetime.now().isoformat()
                        results.append(result)
                        self.total_files_scanned += 1
            else:
                for file in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, file)
                    if os.path.isfile(file_path):
                        result = self.scan_file(file_path)
                        result["timestamp"] = datetime.now().isoformat()
                        results.append(result)
                        self.total_files_scanned += 1
        except Exception as e:
            print(f"Lỗi khi quét thư mục: {e}")
        
        return results
    
    def get_scan_statistics(self):
        """Lấy thống kê quét"""
        return {
            "total_files": self.total_files_scanned,
            "threats_found": self.threats_found,
            "clean_files": self.total_files_scanned - self.threats_found,
            "timestamp": datetime.now().isoformat()
        }


class QuarantineManager:
    """Quản lý các file bị cách ly"""
    
    def __init__(self):
        self.quarantine_dir = os.path.join(os.path.expanduser("~"), ".antivirus-app", "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def quarantine_file(self, file_path):
        """Cách ly một file"""
        try:
            file_hash = calculate_file_hash(file_path)
            if not file_hash:
                return False
            
            # Đổi tên file khi cách ly
            quarantined_name = f"{file_hash}_quarantined"
            quarantined_path = os.path.join(self.quarantine_dir, quarantined_name)
            
            # Di chuyển file vào quarantine
            if os.path.exists(file_path):
                os.rename(file_path, quarantined_path)
                return True
            return False
        except Exception as e:
            print(f"Lỗi khi cách ly file: {e}")
            return False
    
    def restore_file(self, quarantined_name, original_path):
        """Khôi phục file từ quarantine"""
        try:
            quarantined_path = os.path.join(self.quarantine_dir, quarantined_name)
            if os.path.exists(quarantined_path):
                os.rename(quarantined_path, original_path)
                return True
            return False
        except Exception as e:
            print(f"Lỗi khi khôi phục file: {e}")
            return False
    
    def delete_quarantined_file(self, quarantined_name):
        """Xóa file trong quarantine"""
        try:
            quarantined_path = os.path.join(self.quarantine_dir, quarantined_name)
            if os.path.exists(quarantined_path):
                os.remove(quarantined_path)
                return True
            return False
        except Exception as e:
            print(f"Lỗi khi xóa file quarantine: {e}")
            return False
    
    def list_quarantine(self):
        """Liệt kê các file trong quarantine"""
        try:
            files = []
            for file in os.listdir(self.quarantine_dir):
                file_path = os.path.join(self.quarantine_dir, file)
                files.append({
                    "name": file,
                    "path": file_path,
                    "size": os.path.getsize(file_path),
                    "created": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                })
            return files
        except Exception as e:
            print(f"Lỗi khi liệt kê quarantine: {e}")
            return []


def quick_scan(path):
    """Quét nhanh một file hoặc thư mục"""
    scanner = Scanner()
    if os.path.isfile(path):
        return scanner.scan_file(path)
    else:
        return scanner.scan_directory(path)
