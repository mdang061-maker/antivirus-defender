# Ứng dụng Antivirus Defender

Ứng dụng phòng thủ virus và mã độc cho máy tính Windows, phát hiện và ngăn chặn các mối đe dọa bảo mật.

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

## ✨ Tính năng

- 🔍 **Quét virus và mã độc**: Phát hiện và quét file/thư mục để tìm virus, Trojan, Worm, Ransomware, Spyware, Adware
- 🛡️ **Bảo vệ thời gian thực**: Giám sát file hệ thống và cảnh báo khi có thay đổi bất thường
- 📋 **Quản lý danh sách đen/trắng**: Block hoặc cho phép file cụ thể
- 🗂️ **Quản lý quarantine**: Cách ly file độc hại an toàn
- 📊 **Logging và báo cáo**: Ghi lại lịch sử quét và tạo báo cáo thống kê
- 🎯 **Giao diện thân thiện**: Cả giao diện dòng lệnh (CLI) và giao diện đồ họa (GUI)

## 📋 Yêu cầu hệ thống

- **Hệ điều hành**: Windows 10/11
- **Python**: 3.7 hoặc cao hơn
- **RAM**: 2GB trở lên (khuyến nghị 4GB)
- **Disk Space**: 100MB

## 🚀 Cài đặt

### Bước 1: Cài đặt Python

Tải và cài đặt Python từ [python.org](https://www.python.org/downloads/) hoặc Microsoft Store.

**Lưu ý quan trọng**: Trong quá trình cài đặt, hãy đánh dấu tích vào **"Add Python to PATH"**

### Bước 2: Tải ứng dụng

#### Cách 1: Clone từ GitHub
```bash
git clone https://github.com/username/antivirus-defender.git
cd antivirus-defender
```

#### Cách 2: Tải file nén
```bash
# Tải file zip từ GitHub
# Giải nén vào thư mục mong muốn
```

### Bước 3: Chạy ứng dụng

#### Chạy giao diện dòng lệnh (CLI):
```bash
python main.py
```

#### Chạy giao diện đồ họa (GUI):
```bash
python gui.py
```

## 📖 Hướng dẫn sử dụng

### Quét file hoặc thư mục

**Quét file đơn lẻ:**
```bash
1. Chọn tùy chọn "1. Quét file hoặc thư mục"
2. Nhập đường dẫn file (ví dụ: C:\Users\DELL\Documents\file.exe)
3. Nhấn Enter để quét
```

**Quét thư mục:**
```bash
1. Chọn tùy chọn "1. Quét file hoặc thư mục"
2. Nhập đường dẫn thư mục (ví dụ: C:\Users\DELL\Downloads)
3. Chọn "Quét nhanh" hoặc "Quét đầy đủ"
4. Nhấn Enter để quét
```

### Bảo vệ thời gian thực

```bash
1. Chọn tùy chọn "2. Bảo vệ thời gian thực"
2. Nhập "1" để bật bảo vệ
3. Hệ thống sẽ giám sát file hệ thống quan trọng
4. Khi có thay đổi bất thường, hệ thống sẽ cảnh báo
```

### Quản lý danh sách đen (Block)

```bash
1. Chọn tùy chọn "3. Quản lý mối đe dọa"
2. Chọn "3. Thêm vào danh sách đen"
3. Nhập đường dẫn file cần chặn
4. Nhập lý do chặn (tùy chọn)
```

### Quản lý danh sách trắng (Whitelist)

```bash
1. Chọn tùy chọn "3. Quản lý mối đe dọa"
2. Chọn "4. Thêm vào danh sách trắng"
3. Nhập đường dẫn file được phép
4. Nhập lý do (tùy chọn)
```

### Xem thống kê

```bash
1. Chọn tùy chọn "4. Xem thống kê và báo cáo"
2. Xem tổng số file đã quét
3. Xem số lượng mối đe dọa phát hiện
4. Xem thời gian quét cuối cùng
```

## 🛠️ Cấu trúc thư mục

```
antivirus-defender/
├── config.py          # Cấu hình ứng dụng
├── database.py        # Quản lý cơ sở dữ liệu mã độc
├── scanner.py         # Module quét file và phát hiện mã độc
├── monitor.py         # Giám sát file hệ thống
├── threat_manager.py  # Quản lý mối đe dọa
├── logging_mod.py     # Module logging
├── gui.py             # Giao diện đồ họa (GUI)
├── main.py            # Điểm vào chính (CLI)
├── main_cli.py        # Giao diện dòng lệnh
├── README.md          # Tài liệu hướng dẫn
├── requirements.txt   # Danh sách thư viện
└── LICENSE            # Giấy phép
```

## 🔧 Cấu hình nâng cao

### Chỉnh sửa cấu hình

Mở file `config.py` để thay đổi:

```python
# Kích thước file tối đa được quét (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# Khoảng thời gian giám sát (giây)
MONITOR_INTERVAL = 5

# Cấu hình giao diện
UI_WIDTH = 800
UI_HEIGHT = 600
```

## 🐛 Troubleshooting

### Lỗi: "Python was not found"
**Giải pháp**: Cài đặt Python và đảm bảo add vào PATH

### Lỗi: "No module named tkinter"
**Giải pháp**: Tkinter thường đã có sẵn trên Windows. Nếu thiếu, cài lại Python với tùy chọn tkinter.

### Lỗi: "Permission denied"
**Giải pháp**: Chạy PowerShell/Command Prompt với quyền Admin

## 📝 Contributing

Contributions, issues và feature requests đều được chào đón!

## 📄 License

Mã nguồn này được phân phối theo giấy phép [MIT](LICENSE).

## 👥 Tác giả

- **Đặng Nguyễn Duy Minh**
- GitHub: [@antivirus-defender](https://github.com/antivirus-defender)

## ⭐ Show your support

Give a ⭐️ if you like this project!

---

**Lưu ý**: Ứng dụng này là công cụ bảo mật bổ trợ, không thể thay thế phần mềm diệt virus chuyên nghiệp. Hãy sử dụng kết hợp với các phần mềm bảo mật khác để có bảo vệ tối ưu.
