"""
Giao diện đồ họa cho ứng dụng phòng thủ mã độc
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from datetime import datetime
from config import UI_TITLE, UI_WIDTH, UI_HEIGHT
from scanner import Scanner, QuarantineManager
from monitor import FileMonitor, start_real_time_protection
from threat_manager import ThreatManager

class AntivirusGUI:
    """Giao diện người dùng cho ứng dụng phòng thủ mã độc"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(UI_TITLE)
        self.root.geometry(f"{UI_WIDTH}x{UI_HEIGHT}")
        
        # Initialize components
        self.scanner = Scanner()
        self.quarantine = QuarantineManager()
        self.threat_manager = ThreatManager()
        self.file_monitor = FileMonitor()
        
        # Track scanning state
        self.is_scanning = False
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Thiết lập giao diện"""
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scanning tab
        self.scanning_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanning_frame, text="Quét Virus")
        
        # Real-time Protection tab
        self.protection_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.protection_frame, text="Bảo vệ Thời gian Thực")
        
        # Threat Management tab
        self.threat_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_frame, text="Quản lý Mối đe dọa")
        
        # Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Nhật ký Hoạt động")
        
        # Statistics tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Thống kê")
        
        # Setup each tab
        self.setup_scanning_tab()
        self.setup_protection_tab()
        self.setup_threat_tab()
        self.setup_logs_tab()
        self.setup_stats_tab()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Sẵn sàng", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_scanning_tab(self):
        """Thiết lập tab quét virus"""
        # Title
        title_label = ttk.Label(self.scanning_frame, text="Quét máy tính để tìm virus và mã độc", 
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=20)
        
        # File selection
        file_frame = ttk.LabelFrame(self.scanning_frame, text="Chọn file hoặc thư mục")
        file_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.file_path_var = tk.StringVar()
        path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=60)
        path_entry.pack(side=tk.LEFT, padx=10, pady=10, expand=True)
        
        browse_btn = ttk.Button(file_frame, text="Duyệt...", command=self.browse_file)
        browse_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Scan options
        options_frame = ttk.LabelFrame(self.scanning_frame, text="Tùy chọn quét")
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.quick_scan_var = tk.BooleanVar(value=True)
        quick_check = ttk.Checkbutton(options_frame, text="Quét nhanh (khuyên dùng)", 
                                      variable=self.quick_scan_var)
        quick_check.pack(anchor=tk.W, padx=10, pady=5)
        
        # Scan button
        scan_btn = ttk.Button(self.scanning_frame, text="Bắt đầu Quét", 
                             command=self.start_scan, style="Accent.TButton")
        scan_btn.pack(pady=20)
        
        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.scanning_frame, variable=self.progress_var, 
                                         maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20, pady=10)
        self.progress_bar.pack_forget()  # Hide initially
        
        # Results
        results_frame = ttk.LabelFrame(self.scanning_frame, text="Kết quả Quét")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create treeview for results
        columns = ("File", "Status", "Threat", "Type")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="tree headings")
        self.results_tree.heading("#0", text="File")
        self.results_tree.heading("Status", text="Trạng thái")
        self.results_tree.heading("Threat", text="Mối đe dọa")
        self.results_tree.heading("Type", text="Loại")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action buttons
        action_frame = ttk.Frame(self.scanning_frame)
        action_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.action_btn = ttk.Button(action_frame, text="Cách ly", 
                                   command=self.quarantine_selected, state=tk.DISABLED)
        self.action_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_btn = ttk.Button(action_frame, text="Xóa", 
                                   command=self.delete_selected, state=tk.DISABLED)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_btn = ttk.Button(action_frame, text="Làm mới", 
                                    command=self.refresh_results)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
    
    def setup_protection_tab(self):
        """Thiết lập tab bảo vệ thời gian thực"""
        # Status display
        status_frame = ttk.LabelFrame(self.protection_frame, text="Trạng thái Bảo vệ")
        status_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.protection_status_var = tk.StringVar(value="Đang tắt")
        self.protection_status_label = ttk.Label(status_frame, 
                                                textvariable=self.protection_status_var,
                                                font=("Arial", 12, "bold"),
                                                foreground="red")
        self.protection_status_label.pack(pady=10)
        
        # Controls
        control_frame = ttk.Frame(self.protection_frame)
        control_frame.pack(pady=20)
        
        self.enable_btn = ttk.Button(control_frame, text="Bật Bảo vệ", 
                                   command=self.enable_protection)
        self.enable_btn.pack(pady=10, fill=tk.X)
        
        self.disable_btn = ttk.Button(control_frame, text="Tắt Bảo vệ", 
                                    command=self.disable_protection, state=tk.DISABLED)
        self.disable_btn.pack(pady=10, fill=tk.X)
        
        # Protected files count
        protected_frame = ttk.Frame(self.protection_frame)
        protected_frame.pack(pady=20)
        
        self.protected_count_label = ttk.Label(protected_frame, 
                                             text="File đang được giám sát: 0")
        self.protected_count_label.pack()
        
        # Alerts display
        alerts_frame = ttk.LabelFrame(self.protection_frame, text="Cảnh báo")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.alerts_text = tk.Text(alerts_frame, height=15, width=50)
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, 
                                 command=self.alerts_text.yview)
        self.alerts_text.configure(yscroll=scrollbar.set)
        self.alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_threat_tab(self):
        """Thiết lập tab quản lý mối đe dọa"""
        # Blacklist management
        blacklist_frame = ttk.LabelFrame(self.threat_frame, text="Danh sách Đen (Block)")
        blacklist_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create treeview for blacklist
        black_columns = ("Hash", "Reason", "Added Date")
        self.blacklist_tree = ttk.Treeview(blacklist_frame, columns=black_columns, 
                                        show="tree headings", height=10)
        self.blacklist_tree.heading("#0", text="STT")
        self.blacklist_tree.heading("Hash", text="Hash")
        self.blacklist_tree.heading("Reason", text="Lý do")
        self.blacklist_tree.heading("Added Date", text="Ngày thêm")
        
        black_scrollbar = ttk.Scrollbar(blacklist_frame, orient=tk.VERTICAL, 
                                       command=self.blacklist_tree.yview)
        self.blacklist_tree.configure(yscroll=black_scrollbar.set)
        
        self.blacklist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        black_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        black_button_frame = ttk.Frame(self.threat_frame)
        black_button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Button(black_button_frame, text="Xóa khỏi Danh sách Đen", 
                  command=self.remove_from_blacklist).pack(side=tk.LEFT, padx=5)
        ttk.Button(black_button_frame, text="Xuất Danh sách Đen", 
                  command=self.export_blacklist).pack(side=tk.LEFT, padx=5)
        
        # Whitelist management
        whitelist_frame = ttk.LabelFrame(self.threat_frame, text="Danh sách Trắng (Whitelist)")
        whitelist_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create treeview for whitelist
        white_columns = ("Hash", "Reason", "Added Date")
        self.whitelist_tree = ttk.Treeview(whitelist_frame, columns=white_columns, 
                                        show="tree headings", height=10)
        self.whitelist_tree.heading("#0", text="STT")
        self.whitelist_tree.heading("Hash", text="Hash")
        self.whitelist_tree.heading("Reason", text="Lý do")
        self.whitelist_tree.heading("Added Date", text="Ngày thêm")
        
        white_scrollbar = ttk.Scrollbar(whitelist_frame, orient=tk.VERTICAL, 
                                       command=self.whitelist_tree.yview)
        self.whitelist_tree.configure(yscroll=white_scrollbar.set)
        
        self.whitelist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        white_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Whitelist buttons
        white_button_frame = ttk.Frame(self.threat_frame)
        white_button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Button(white_button_frame, text="Xóa khỏi Danh sách Trắng", 
                  command=self.remove_from_whitelist).pack(side=tk.LEFT, padx=5)
    
    def setup_logs_tab(self):
        """Thiết lập tab nhật ký"""
        # Logs display
        logs_frame = ttk.LabelFrame(self.logs_frame, text="Nhật ký Hoạt động")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.logs_text = tk.Text(logs_frame, height=20, width=70)
        scrollbar = ttk.Scrollbar(logs_frame, orient=tk.VERTICAL, 
                                 command=self.logs_text.yview)
        self.logs_text.configure(yscroll=scrollbar.set)
        self.logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        log_button_frame = ttk.Frame(self.logs_frame)
        log_button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(log_button_frame, text="Tải lại Nhật ký", 
                  command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_button_frame, text="Xóa Nhật ký", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=5)
    
    def setup_stats_tab(self):
        """Thiết lập tab thống kê"""
        # Stats display
        stats_frame = ttk.Frame(self.stats_frame)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Total files scanned
        ttk.Label(stats_frame, text="Tổng số file đã quét:", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.total_scanned_label = ttk.Label(stats_frame, text="0", 
                                         font=("Arial", 12))
        self.total_scanned_label.pack(anchor=tk.W, pady=5)
        
        # Threats found
        ttk.Label(stats_frame, text="Mối đe dọa đã phát hiện:", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.threats_found_label = ttk.Label(stats_frame, text="0", 
                                         font=("Arial", 12, "bold"), foreground="red")
        self.threats_found_label.pack(anchor=tk.W, pady=5)
        
        # Clean files
        ttk.Label(stats_frame, text="File an toàn:", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.clean_files_label = ttk.Label(stats_frame, text="0", 
                                       font=("Arial", 12))
        self.clean_files_label.pack(anchor=tk.W, pady=5)
        
        # Last scan time
        ttk.Label(stats_frame, text="Lần quét cuối:", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)
        self.last_scan_label = ttk.Label(stats_frame, text="Chưa quét", 
                                       font=("Arial", 12))
        self.last_scan_label.pack(anchor=tk.W, pady=5)
        
        # Update button
        ttk.Button(stats_frame, text="Cập nhật Thống kê", 
                  command=self.update_stats).pack(pady=20)
    
    def browse_file(self):
        """Mở dialog chọn file hoặc thư mục"""
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.file_path_var.set(path)
    
    def start_scan(self):
        """Bắt đầu quét"""
        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Lỗi", "Vui lòng chọn file hoặc thư mục để quét!")
            return
        
        if self.is_scanning:
            messagebox.showinfo("Thông báo", "Đang quét, vui lòng đợi!")
            return
        
        self.is_scanning = True
        self.scanning_frame.config(cursor="watch")
        
        # Run scan in a separate thread
        scan_thread = threading.Thread(target=self._run_scan, args=(path,))
        scan_thread.start()
    
    def _run_scan(self, path):
        """Chạy quét trong thread riêng"""
        try:
            if self.quick_scan_var.get():
                result = self.scanner.scan_file(path)
                self.root.after(0, self._update_scan_result, result)
            else:
                if path.endswith('\\') or path.endswith('/'):
                    results = self.scanner.scan_directory(path, recursive=True)
                else:
                    results = [self.scanner.scan_file(path)]
                self.root.after(0, self._update_scan_results, results)
        finally:
            self.scanning_frame.config(cursor="")
            self.is_scanning = False
    
    def _update_scan_result(self, result):
        """Cập nhật kết quả quét"""
        self.add_result_to_tree(result)
        self.update_status_bar(result)
    
    def _update_scan_results(self, results):
        """Cập nhật nhiều kết quả quét"""
        for result in results:
            self.add_result_to_tree(result)
        self.update_status_bar({"total": len(results)})
    
    def add_result_to_tree(self, result):
        """Thêm kết quả vào treeview"""
        file_path = result.get("file_path", "Unknown")
        status = result.get("status", "unknown")
        threat_name = result.get("threat_name", "")
        threat_type = result.get("threat_type", "")
        
        if status == "threat":
            tag = "threat"
        elif status == "clean" or status == "whitelisted":
            tag = "clean"
        elif status == "suspicious":
            tag = "suspicious"
        else:
            tag = "default"
        
        self.results_tree.insert("", "end", text=file_path, 
                                values=(status, threat_name, threat_type), tags=(tag,))
    
    def setup_treeview_tags(self):
        """Thiết lập tags cho treeview"""
        self.results_tree.tag_configure("threat", foreground="red")
        self.results_tree.tag_configure("clean", foreground="green")
        self.results_tree.tag_configure("suspicious", foreground="orange")
    
    def quarantine_selected(self):
        """Cách ly file được chọn"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Lỗi", "Vui lòng chọn file để cách ly!")
            return
        
        item = self.results_tree.item(selection[0])
        file_path = item["text"]
        
        if self.quarantine.quarantine_file(file_path):
            messagebox.showinfo("Thành công", f"File đã được cách ly: {file_path}")
            self.refresh_results()
        else:
            messagebox.showerror("Lỗi", "Không thể cách ly file!")
    
    def delete_selected(self):
        """Xóa file được chọn"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Lỗi", "Vui lòng chọn file để xóa!")
            return
        
        item = self.results_tree.item(selection[0])
        file_path = item["text"]
        
        if messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn xóa file: {file_path}?"):
            if self.threat_manager.threat_manager_file_handler.delete_file(file_path):
                messagebox.showinfo("Thành công", f"File đã được xóa: {file_path}")
                self.refresh_results()
            else:
                messagebox.showerror("Lỗi", "Không thể xóa file!")
    
    def refresh_results(self):
        """Làm mới kết quả"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
    
    def update_status_bar(self, result):
        """Cập nhật status bar"""
        if result.get("status") == "threat":
            self.status_bar.config(text=f"Đã phát hiện mối đe dọa: {result.get('threat_name', 'Unknown')}")
        elif result.get("status") == "clean":
            self.status_bar.config(text=f"File an toàn: {result.get('file_path', 'Unknown')}")
        else:
            total = result.get("total", 0)
            self.status_bar.config(text=f"Đã quét {total} file")
    
    def enable_protection(self):
        """Bật bảo vệ thời gian thực"""
        self.file_monitor.start_monitoring()
        self.protection_status_var.set("Đang bật")
        self.protection_status_label.config(foreground="green")
        self.enable_btn.config(state=tk.DISABLED)
        self.disable_btn.config(state=tk.NORMAL)
        
        self.protected_count_label.config(
            text=f"File đang được giám sát: {len(self.file_monitor.monitored_files)}"
        )
        
        self.add_log("Bảo vệ thời gian thực đã được bật")
    
    def disable_protection(self):
        """Tắt bảo vệ thời gian thực"""
        self.file_monitor.stop_monitoring()
        self.protection_status_var.set("Đang tắt")
        self.protection_status_label.config(foreground="red")
        self.enable_btn.config(state=tk.NORMAL)
        self.disable_btn.config(state=tk.DISABLED)
        
        self.protected_count_label.config(text="File đang được giám sát: 0")
        
        self.add_log("Bảo vệ thời gian thực đã được tắt")
    
    def add_log(self, message):
        """Thêm log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.logs_text.insert(tk.END, log_entry)
    
    def refresh_logs(self):
        """Làm mới nhật ký"""
        # Placeholder for log refresh logic
        pass
    
    def clear_logs(self):
        """Xóa nhật ký"""
        if messagebox.askyesno("Xác nhận", "Bạn có chắc muốn xóa tất cả nhật ký?"):
            self.logs_text.delete(1.0, tk.END)
            self.add_log("Đã xóa tất cả nhật ký")
    
    def update_stats(self):
        """Cập nhật thống kê"""
        stats = self.scanner.get_scan_statistics()
        
        self.total_scanned_label.config(text=str(stats.get("total_files", 0)))
        self.threats_found_label.config(text=str(stats.get("threats_found", 0)))
        self.clean_files_label.config(text=str(stats.get("clean_files", 0)))
        
        last_scan = stats.get("timestamp", "Chưa quét")
        self.last_scan_label.config(text=last_scan)
    
    def export_blacklist(self):
        """Xuất danh sách đen"""
        output_file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if output_file:
            result = self.threat_manager.threat_manager_file_handler.export_blacklist(output_file)
            if result["status"] == "success":
                messagebox.showinfo("Thành công", f"Danh sách đen đã được xuất: {output_file}")
            else:
                messagebox.showerror("Lỗi", result["message"])
    
    def remove_from_blacklist(self):
        """Xóa khỏi danh sách đen"""
        # Placeholder for blacklist removal logic
        messagebox.showinfo("Thông báo", "Chức năng này sẽ được phát triển thêm")
    
    def remove_from_whitelist(self):
        """Xóa khỏi danh sách trắng"""
        # Placeholder for whitelist removal logic
        messagebox.showinfo("Thông báo", "Chức năng này sẽ được phát triển thêm")
    
    def add_result_to_tree(self, result):
        """Thêm kết quả vào treeview"""
        # Check if treeview is initialized
        if not hasattr(self, 'results_tree'):
            return
        
        file_path = result.get("file_path", "Unknown")
        status = result.get("status", "unknown")
        threat_name = result.get("threat_name", "")
        threat_type = result.get("threat_type", "")
        
        # Initialize tags if not already done
        if not hasattr(self, '_tags_setup'):
            self.results_tree.tag_configure("threat", foreground="red")
            self.results_tree.tag_configure("clean", foreground="green")
            self.results_tree.tag_configure("suspicious", foreground="orange")
            self._tags_setup = True
        
        if status == "threat":
            tag = "threat"
        elif status == "clean" or status == "whitelisted":
            tag = "clean"
        elif status == "suspicious":
            tag = "suspicious"
        else:
            tag = "default"
        
        self.results_tree.insert("", "end", text=file_path, 
                                values=(status, threat_name, threat_type), tags=(tag,))
    
    def refresh_results(self):
        """Làm mới kết quả"""
        if hasattr(self, 'results_tree'):
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
    
    def update_status_bar(self, result):
        """Cập nhật status bar"""
        if not hasattr(self, 'status_bar'):
            return
        
        if result.get("status") == "threat":
            self.status_bar.config(text=f"Đã phát hiện mối đe dọa: {result.get('threat_name', 'Unknown')}")
        elif result.get("status") == "clean":
            self.status_bar.config(text=f"File an toàn: {result.get('file_path', 'Unknown')}")
        else:
            total = result.get("total", 0)
            self.status_bar.config(text=f"Đã quét {total} file")
    
    def add_log(self, message):
        """Thêm log"""
        if not hasattr(self, 'logs_text'):
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.logs_text.insert(tk.END, log_entry)

def main():
    """Hàm chính"""
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
