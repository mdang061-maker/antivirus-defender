"""
Cấu hình ứng dụng phòng thủ mã độc
"""
import os

# Cấu hình thư mục làm việc
APP_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".antivirus-app")

# Cấu hình file dữ liệu
MALWARE_DB_FILE = os.path.join(WORKSPACE_DIR, "malware_db.txt")
SCAN_LOG_FILE = os.path.join(WORKSPACE_DIR, "scan_logs.txt")
BLACKLIST_FILE = os.path.join(WORKSPACE_DIR, "blacklist.txt")
WHITELIST_FILE = os.path.join(WORKSPACE_DIR, "whitelist.txt")

# Cấu hình quét virus
SCAN_CHUNK_SIZE = 8192  # Đọc file theo từng chunk 8KB
MAX_FILE_SIZE = 100 * 1024 * 1024  # Giới hạn 100MB cho file quét

# Cấu hình giám sát
MONITOR_ENABLED = True
MONITOR_INTERVAL = 5  # Kiểm tra mỗi 5 giây

# Cấu hình giao diện
UI_TITLE = "Antivirus Defender - Ứng dụng Phòng thủ Mã độc"
UI_WIDTH = 800
UI_HEIGHT = 600
