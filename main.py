"""
Main application file cho ứng dụng phòng thủ mã độc
"""
import sys
import os

# Thêm đường dẫn hiện tại vào sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import Scanner, QuarantineManager
from monitor import FileMonitor, RealTimeProtection
from threat_manager import ThreatManager
from logging_mod import AntivirusLogger, ReportGenerator
from database import init_databases


def init_environment():
    """Khởi tạo môi trường"""
    print("Đang khởi tạo ứng dụng...")
    print("Kiểm tra môi trường...")
    
    # Kiểm tra Python version
    if sys.version_info < (3, 7):
        print("Lỗi: Ứng dụng yêu cầu Python 3.7 hoặc cao hơn")
        sys.exit(1)
    
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    
    # Tạo các thư mục cần thiết
    app_dir = os.path.join(os.path.expanduser("~"), ".antivirus-app")
    os.makedirs(app_dir, exist_ok=True)
    os.makedirs(os.path.join(app_dir, "quarantine"), exist_ok=True)
    
    print(f"Đã tạo thư mục làm việc: {app_dir}")
    print("Khởi tạo hoàn tất!\n")


def test_basic_functionality():
    """Test chức năng cơ bản"""
    print("Đang test chức năng cơ bản...")
    
    # Khởi tạo database
    print("\n1. Khởi tạo Database:")
    malware_db = init_databases()
    print(f"   ✓ Database đã được khởi tạo")
    print(f"   ✓ Có {len(malware_db.malware_db)} mẫu mã độc trong database")
    
    # Test scanner
    print("\n2. Test Scanner:")
    scanner = Scanner()
    print(f"   ✓ Scanner đã được khởi tạo")
    
    # Tạo file test
    test_file = os.path.join(os.path.expanduser("~"), ".antivirus-app", "test_file.txt")
    with open(test_file, 'w') as f:
        f.write("Đây là file test")
    
    print(f"   ✓ Đã tạo file test: {test_file}")
    
    # Quét file test
    print("\n3. Quét file test:")
    result = scanner.scan_file(test_file)
    print(f"   ✓ Kết quả: {result.get('status', 'unknown')}")
    print(f"   ✓ Hash: {result.get('hash', 'N/A')}")
    
    # Test quarantine
    print("\n4. Test Quarantine:")
    quarantine = QuarantineManager()
    print(f"   ✓ Quarantine đã được khởi tạo")
    print(f"   ✓ Thư mục quarantine: {quarantine.quarantine_dir}")
    
    # Test monitor
    print("\n5. Test Monitor:")
    monitor = FileMonitor()
    print(f"   ✓ Monitor đã được khởi tạo")
    
    # Test protection
    print("\n6. Test Real-time Protection:")
    protection = RealTimeProtection()
    print(f"   ✓ Bảo vệ đã được khởi tạo")
    
    # Test threat manager
    print("\n7. Test Threat Manager:")
    tm = ThreatManager()
    print(f"   ✓ Threat Manager đã được khởi tạo")
    
    # Test logging
    print("\n8. Test Logging:")
    logger = AntivirusLogger()
    print(f"   ✓ Logger đã được khởi tạo")
    print(f"   ✓ Log file: {logger.log_file}")
    
    # Test report generator
    print("\n9. Test Report Generator:")
    report_gen = ReportGenerator()
    print(f"   ✓ Report Generator đã được khởi tạo")
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
        print(f"\n✓ Đã xóa file test")
    
    print("\n" + "="*50)
    print("Tất cả chức năng đã được test thành công!")
    print("="*50)


def main_entry():
    """Điểm vào chính của ứng dụng"""
    try:
        # Khởi tạo môi trường
        init_environment()
        
        # Chạy test
        print("\nChạy test chức năng cơ bản...")
        test_basic_functionality()
        
    except KeyboardInterrupt:
        print("\n\nỨng dụng đã bị dừng bởi người dùng")
    except Exception as e:
        print(f"Lỗi: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main_entry()
