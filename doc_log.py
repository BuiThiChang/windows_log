import pandas as pd  # Thư viện Pandas xử lý bảng dữ liệu log 

# 1. Đọc file log CSV (Giả sử bạn có file 'windows_logs.csv' trong thư mục)
# Nếu chưa có file, bạn có thể tạo một file CSV giả lập để test trước
try:
    df = pd.read_csv("windows_logs.csv")
    print("--- Đọc file log thành công! ---")
    
    # Hiển thị 5 dòng log đầu tiên để kiểm tra cấu trúc [cite: 9]
    print("\n5 dòng log đầu tiên:")
    print(df.head())
    
    # 2. Lọc và đếm các Event ID quan trọng [cite: 14]
    # Ví dụ: Event ID 4625 là đăng nhập thất bại [cite: 14]
    if 'EventID' in df.columns:
        login_failures = df[df['EventID'] == 4625]
        print(f"\nSố lượng sự kiện đăng nhập thất bại (Event ID 4625): {len(login_failures)}")
        
        # Thống kê tổng số lượng theo từng Event ID
        print("\nThống kê số lượng theo từng Event ID:")
        print(df['EventID'].value_counts())
    else:
        print("\nKhông tìm thấy cột 'EventID' trong file log.")

except FileNotFoundError:
    print("Chưa tìm thấy file 'windows_logs.csv'. Hãy kiểm tra lại đường dẫn!")