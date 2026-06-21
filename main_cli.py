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
from logging import Logger, ReportGenerator


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


def create_cl_menu():
    """Tạo menu dòng lệnh"""
    print("=" * 50)
    print("ỨNG DỤNG PHÒNG THỦ MÃ ĐỘC")
    print("=" * 50)
    print("1. Quét file hoặc thư mục")
    print("2. Bảo vệ thời gian thực")
    print("3. Quản lý danh sách đen/trắng")
    print("4. Xem thống kê và báo cáo")
    print("5. Thoát")
    print("-" * 50)


def scan_file_or_directory(scanner, quarantine):
    """Quét file hoặc thư mục"""
    print("\n--- QUÉT FILE/THƯ MỤC ---")
    path = input("Nhập đường dẫn file hoặc thư mục: ").strip()
    
    if not path:
        print("Đường dẫn không hợp lệ!")
        return
    
    if not os.path.exists(path):
        print("File hoặc thư mục không tồn tại!")
        return
    
    print(f"\nĐang quét: {path}")
    print("Vui lòng đợi...")
    
    if os.path.isfile(path):
        result = scanner.scan_file(path)
        print_scan_result(result)
    else:
        results = scanner.scan_directory(path, recursive=True)
        print_scan_results(results)


def print_scan_result(result):
    """In kết quả quét"""
    print("\n" + "=" * 50)
    print("KẾT QUẢ QUÉT")
    print("=" * 50)
    print(f"File: {result.get('file_path', 'Unknown')}")
    print(f"Trạng thái: {result.get('status', 'Unknown')}")
    print(f"Hash: {result.get('hash', 'N/A')}")
    
    if result.get('status') == 'threat':
        print(f"Mối đe dọa: {result.get('threat_name', 'Unknown')}")
        print(f"Loại: {result.get('threat_type', 'Unknown')}")
        print("\n⚠️  ĐÃ PHÁT HIỆN MỐI ĐE DỌA!")
        
        action = input("Bạn muốn làm gì? (c: Cách ly, x: Xóa, b: Bỏ qua): ").lower()
        if action == 'c':
            if quarantine.quarantine_file(result.get('file_path')):
                print("File đã được cách ly thành công!")
            else:
                print("Không thể cách ly file!")
        elif action == 'x':
            if os.path.exists(result.get('file_path')):
                os.remove(result.get('file_path'))
                print("File đã được xóa!")
    
    print("=" * 50)


def print_scan_results(results):
    """In nhiều kết quả quét"""
    print("\n" + "=" * 50)
    print("KẾT QUẢ QUÉT")
    print("=" * 50)
    
    threats = 0
    for result in results:
        if result.get('status') == 'threat':
            threats += 1
            print(f"⚠️  {result.get('file_path')}: {result.get('threat_name', 'Unknown')}")
        elif result.get('status') == 'clean':
            print(f"✓ {result.get('file_path')}: An toàn")
    
    stats = scanner.get_scan_statistics()
    print(f"\nTổng: {stats['total_files']} file")
    print(f"Đe dọa: {stats['threats_found']}")
    print(f"An toàn: {stats['clean_files']}")
    print("=" * 50)


def real_time_protection():
    """Bảo vệ thời gian thực"""
    print("\n--- BẢO VỆ THỜI GIAN THỰC ---")
    protection = RealTimeProtection()
    
    print("1. Bật bảo vệ")
    print("2. Tắt bảo vệ")
    print("3. Xem trạng thái")
    choice = input("Chọn chức năng (1-3): ").strip()
    
    if choice == '1':
        protection.enable_protection()
        print("Bảo vệ thời gian thực đã được bật!")
        print("Đang giám sát file hệ thống...")
    elif choice == '2':
        protection.disable_protection()
        print("Bảo vệ thời gian thực đã được tắt!")
    elif choice == '3':
        status = protection.get_status()
        print(f"\nTrạng thái: {'Đang bật' if status['enabled'] else 'Đang tắt'}")
        print(f"File giám sát: {status['monitoring_files']}")
        print(f"Cảnh báo: {status['alerts_count']}")


def threat_management(threat_manager):
    """Quản lý mối đe dọa"""
    print("\n--- QUẢN LÝ MỐI ĐE DỌA ---")
    
    while True:
        print("1. Xem danh sách đen")
        print("2. Xem danh sách trắng")
        print("3. Thêm vào danh sách đen")
        print("4. Thêm vào danh sách trắng")
        print("5. Xóa khỏi danh sách")
        print("6. Quay lại")
        
        choice = input("Chọn chức năng (1-6): ").strip()
        
        if choice == '1':
            blacklist = threat_manager.get_blacklist()
            print("\nDANH SÁCH ĐEN:")
            for item in blacklist:
                print(f"  - {item['hash']}: {item.get('reason', 'N/A')}")
        
        elif choice == '2':
            whitelist = threat_manager.get_whitelist()
            print("\nDANH SÁCH TRẮNG:")
            for item in whitelist:
                print(f"  - {item['hash']}: {item.get('reason', 'N/A')}")
        
        elif choice == '3':
            path = input("Nhập đường dẫn file: ").strip()
            reason = input("Nhập lý do: ").strip()
            result = threat_manager.block_file(path, reason)
            print(f"Kết quả: {result['status']}")
        
        elif choice == '4':
            path = input("Nhập đường dẫn file: ").strip()
            reason = input("Nhập lý do: ").strip()
            result = threat_manager.whitelist_file(path, reason)
            print(f"Kết quả: {result['status']}")
        
        elif choice == '5':
            hash_val = input("Nhập hash cần xóa: ").strip()
            source = input("Danh sách đen (b) hoặc trắng (w)?: ").lower()
            if source == 'b':
                threat_manager.unblock_file(hash_val)
                print("Đã xóa khỏi danh sách đen!")
            else:
                threat_manager.unwhitelist_file(hash_val)
                print("Đã xóa khỏi danh sách trắng!")
        
        elif choice == '6':
            break


def view_statistics(scanner):
    """Xem thống kê"""
    print("\n--- THỐNG KÊ ---")
    
    stats = scanner.get_scan_statistics()
    
    print(f"\nTổng số file đã quét: {stats.get('total_files', 0)}")
    print(f"Mối đe dọa đã phát hiện: {stats.get('threats_found', 0)}")
    print(f"File an toàn: {stats.get('clean_files', 0)}")
    print(f"Thời gian: {stats.get('timestamp', 'N/A')}")


def main_entry():
    """Điểm vào chính của ứng dụng"""
    try:
        # Khởi tạo môi trường
        init_environment()
        
        # Khởi tạo components
        scanner = Scanner()
        quarantine = QuarantineManager()
        threat_manager = ThreatManager()
        
        # Chạy ứng dụng
        while True:
            create_cl_menu()
            choice = input("Chọn chức năng (1-5): ").strip()
            
            if choice == '1':
                scan_file_or_directory(scanner, quarantine)
            elif choice == '2':
                real_time_protection()
            elif choice == '3':
                threat_management(threat_manager)
            elif choice == '4':
                view_statistics(scanner)
            elif choice == '5':
                print("Cảm ơn bạn đã sử dụng ứng dụng!")
                break
            else:
                print("Lựa chọn không hợp lệ!")
    
    except KeyboardInterrupt:
        print("\n\nỨng dụng đã bị dừng bởi người dùng")
    except Exception as e:
        print(f"Lỗi: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main_entry()
