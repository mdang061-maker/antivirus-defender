"""
Module logging và báo cáo cho ứng dụng phòng thủ mã độc
"""
import os
import json
import logging as pylogging
import sys
from datetime import datetime

# Đảm bảo không bị import từ file logging.py trong thư mục hiện tại
if 'logging' in sys.modules:
    del sys.modules['logging']

from config import SCAN_LOG_FILE, WORKSPACE_DIR

# Tạo thư mục làm việc nếu chưa tồn tại
os.makedirs(WORKSPACE_DIR, exist_ok=True)


class AntivirusLogger:
    """Module logging cho ứng dụng"""
    
    def __init__(self, log_file=None):
        self.log_file = log_file or SCAN_LOG_FILE
        self.scan_results = []
        self._logger = self._setup_logging()
    
    def _setup_logging(self):
        """Thiết lập logging"""
        logger = pylogging.getLogger("antivirus_app")
        logger.setLevel(pylogging.INFO)
        
        # Clear existing handlers
        logger.handlers = []
        
        # Add file handler
        file_handler = pylogging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(pylogging.INFO)
        file_format = pylogging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
        
        # Add stream handler
        stream_handler = pylogging.StreamHandler()
        stream_handler.setLevel(pylogging.INFO)
        stream_handler.setFormatter(file_format)
        logger.addHandler(stream_handler)
        
        return logger
    
    def log_scan(self, file_path, status, threat_name=None, threat_type=None):
        """Ghi lại kết quả quét"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "file_path": file_path,
            "status": status,
            "threat_name": threat_name,
            "threat_type": threat_type
        }
        
        self.scan_results.append(log_entry)
        self._logger.info(f"Quét: {file_path} - {status}")
        
        if threat_name:
            self._logger.warning(f"Phát hiện: {threat_name} ({threat_type})")
    
    def log_threat_detected(self, file_path, threat_name, threat_type):
        """Ghi lại mối đe dọa được phát hiện"""
        self.log_scan(file_path, "threat", threat_name, threat_type)
    
    def log_file_clean(self, file_path):
        """Ghi lại file an toàn"""
        self.log_scan(file_path, "clean")
    
    def log_error(self, message):
        """Ghi lại lỗi"""
        self._logger.error(message)
    
    def log_info(self, message):
        """Ghi lại thông tin"""
        self._logger.info(message)
    
    def log_warning(self, message):
        """Ghi lại cảnh báo"""
        self._logger.warning(message)
    
    def save_scan_results(self, output_file=None):
        """Lưu kết quả quét vào file"""
        output_file = output_file or self.log_file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2)
            self._logger.info(f"Đã lưu kết quả quét vào: {output_file}")
        except Exception as e:
            self._logger.error(f"Lỗi khi lưu kết quả: {e}")
    
    def get_scan_history(self, limit=100):
        """Lấy lịch sử quét"""
        return self.scan_results[-limit:]
    
    def clear_logs(self):
        """Xóa log"""
        self.scan_results = []
        self._logger.info("Đã xóa tất cả log")


class ReportGenerator:
    """Tạo báo cáo từ kết quả quét"""
    
    def __init__(self, logger=None):
        self.logger = logger or AntivirusLogger()
    
    def generate_scan_report(self, scan_results):
        """Tạo báo cáo từ kết quả quét"""
        if not scan_results:
            return None
        
        # Tính toán thống kê
        total_files = len(scan_results)
        threats = sum(1 for r in scan_results if r.get("status") == "threat")
        clean_files = total_files - threats
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_files_scanned": total_files,
                "threats_found": threats,
                "clean_files": clean_files,
                "threat_rate": f"{(threats/total_files*100):.2f}%" if total_files > 0 else "0%"
            },
            "details": scan_results
        }
        
        return report
    
    def generate_daily_report(self, log_file=None):
        """Tạo báo cáo hàng ngày"""
        log_file = log_file or self.logger.log_file
        
        # Đọc log từ file
        daily_results = []
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    # Parse log lines (simplified)
                    if "Quét:" in line and "Phát hiện:" not in line:
                        # This is a simplified parser - in production, use better log parsing
                        pass
        except Exception as e:
            self.logger.error(f"Lỗi khi đọc log: {e}")
        
        return self.generate_scan_report(daily_results)
    
    def export_report(self, report, output_file):
        """Xuất báo cáo ra file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"Đã xuất báo cáo: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi xuất báo cáo: {e}")
            return False
    
    def generate_summary_report(self, scan_results):
        """Tạo báo cáo tóm tắt"""
        if not scan_results:
            return {
                "message": "Không có kết quả quét để tạo báo cáo"
            }
        
        # Group results by status
        status_counts = {}
        threat_types = {}
        
        for result in scan_results:
            status = result.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            
            if status == "threat":
                threat_type = result.get("threat_type", "Unknown")
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        summary = {
            "total_files": len(scan_results),
            "status_breakdown": status_counts,
            "threat_types": threat_types,
            "generated_at": datetime.now().isoformat()
        }
        
        return summary


class AlertSystem:
    """Hệ thống cảnh báo"""
    
    def __init__(self):
        self.alerts = []
        self.alert_types = {
            "high": {"color": "red", "priority": 1},
            "medium": {"color": "orange", "priority": 2},
            "low": {"color": "yellow", "priority": 3}
        }
    
    def add_alert(self, message, alert_type="medium"):
        """Thêm cảnh báo"""
        alert = {
            "message": message,
            "type": alert_type,
            "priority": self.alert_types[alert_type]["priority"],
            "timestamp": datetime.now().isoformat()
        }
        self.alerts.append(alert)
        
        # Sort alerts by priority
        self.alerts.sort(key=lambda x: x["priority"])
    
    def get_alerts(self, limit=10):
        """Lấy cảnh báo"""
        return self.alerts[-limit:]
    
    def clear_alerts(self):
        """Xóa cảnh báo"""
        self.alerts = []
    
    def get_high_priority_alerts(self):
        """Lấy cảnh báo ưu tiên cao"""
        return [alert for alert in self.alerts if alert["priority"] == 1]


def create_logger(log_file=None):
    """Tạo một đối tượng AntivirusLogger"""
    return AntivirusLogger(log_file)


def create_report_generator():
    """Tạo một đối tượng ReportGenerator"""
    return ReportGenerator()


def create_alert_system():
    """Tạo một đối tượng AlertSystem"""
    return AlertSystem()
