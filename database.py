"""
Module quản lý cơ sở dữ liệu cho ứng dụng phòng thủ mã độc
"""
import os
import json
import hashlib
from datetime import datetime
from config import WORKSPACE_DIR, MALWARE_DB_FILE, BLACKLIST_FILE, WHITELIST_FILE

# Tạo thư mục làm việc nếu chưa tồn tại
os.makedirs(WORKSPACE_DIR, exist_ok=True)


class MalwareDatabase:
    """Quản lý cơ sở dữ liệu mã độc"""
    
    def __init__(self):
        self.malware_db = self._load_malware_db()
        self.blacklist = self._load_list(BLACKLIST_FILE)
        self.whitelist = self._load_list(WHITELIST_FILE)
    
    def _load_malware_db(self):
        """Tải cơ sở dữ liệu mã độc từ file"""
        if os.path.exists(MALWARE_DB_FILE):
            try:
                with open(MALWARE_DB_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _load_list(self, file_path):
        """Tải danh sách từ file"""
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_malware_db(self):
        """Lưu cơ sở dữ liệu mã độc vào file"""
        try:
            with open(MALWARE_DB_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.malware_db, f, indent=2)
        except Exception as e:
            print(f"Lỗi khi lưu malware DB: {e}")
    
    def save_list(self, file_path, data):
        """Lưu danh sách vào file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Lỗi khi lưu list: {e}")
    
    def add_malware(self, name, file_hash, file_type, description=""):
        """Thêm mẫu mã độc vào database"""
        self.malware_db[file_hash] = {
            "name": name,
            "hash": file_hash,
            "type": file_type,
            "description": description,
            "added_date": datetime.now().isoformat()
        }
        self.save_malware_db()
    
    def remove_malware(self, file_hash):
        """Xóa mẫu mã độc khỏi database"""
        if file_hash in self.malware_db:
            del self.malware_db[file_hash]
            self.save_malware_db()
    
    def is_malware(self, file_hash):
        """Kiểm tra xem file có phải là mã độc không"""
        return file_hash in self.malware_db
    
    def get_malware_info(self, file_hash):
        """Lấy thông tin về mã độc"""
        return self.malware_db.get(file_hash)
    
    def add_to_blacklist(self, file_hash, reason=""):
        """Thêm file vào danh sách đen"""
        if file_hash not in self.blacklist:
            self.blacklist.append({
                "hash": file_hash,
                "reason": reason,
                "added_date": datetime.now().isoformat()
            })
            self.save_list(BLACKLIST_FILE, self.blacklist)
    
    def remove_from_blacklist(self, file_hash):
        """Xóa file khỏi danh sách đen"""
        self.blacklist = [item for item in self.blacklist if item["hash"] != file_hash]
        self.save_list(BLACKLIST_FILE, self.blacklist)
    
    def is_blacklisted(self, file_hash):
        """Kiểm tra file có nằm trong danh sách đen không"""
        return any(item["hash"] == file_hash for item in self.blacklist)
    
    def add_to_whitelist(self, file_hash, reason=""):
        """Thêm file vào danh sách trắng"""
        if file_hash not in self.whitelist:
            self.whitelist.append({
                "hash": file_hash,
                "reason": reason,
                "added_date": datetime.now().isoformat()
            })
            self.save_list(WHITELIST_FILE, self.whitelist)
    
    def remove_from_whitelist(self, file_hash):
        """Xóa file khỏi danh sách trắng"""
        self.whitelist = [item for item in self.whitelist if item["hash"] != file_hash]
        self.save_list(WHITELIST_FILE, self.whitelist)
    
    def is_whitelisted(self, file_hash):
        """Kiểm tra file có nằm trong danh sách trắng không"""
        return any(item["hash"] == file_hash for item in self.whitelist)


def calculate_file_hash(file_path):
    """Tính toán hash SHA256 của file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None


def init_databases():
    """Khởi tạo cơ sở dữ liệu"""
    malware_db = MalwareDatabase()
    
    # Thêm mẫu mã độc demo (chỉ để test)
    if not malware_db.malware_db:
        malware_db.add_malware("Demo.Trojan.Test", 
                              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                              "Trojan", "Mẫu thử nghiệm - không phải mã độc thật")
    
    return malware_db
