import pandas as pd
from sklearn.ensemble import IsolationForest
import os

# Đường dẫn file dữ liệu đã thu thập
CSV_FILE_PATH = "windows_security_dataset.csv"

def train_and_detect_anomalies():
    # 1. Kiểm tra xem file dữ liệu đã có dữ liệu chưa
    if not os.path.exists(CSV_FILE_PATH):
        print(f"[!] Không tìm thấy file {CSV_FILE_PATH}. Hãy chạy file realtime_log.py trước để gom dữ liệu!")
        return

    # 2. Đọc dữ liệu từ file CSV vào bảng Pandas DataFrame
    df = pd.read_csv(CSV_FILE_PATH)
    
    if len(df) < 5:
        print("[!] Dữ liệu quá ít (cần tối thiểu 5 dòng). Hãy tạo thêm log hệ thống để AI phân tích chính xác hơn!")
        return

    print(f"[*] Đang nạp {len(df)} bản ghi log vào mô hình AI...")

    # 3. Chọn các thuộc tính số (Features) làm đầu vào cho mô hình AI
    # Thuật toán AI chỉ hiểu các cột có giá trị là số
    features = ['EventID', 'Log_Length', 'Suspicious_Keywords', 'Is_Admin_Action']
    X = df[features]

    # 4. Khởi tạo mô hình Isolation Forest (Rừng cô lập)
    # contamination=0.05 nghĩa là chúng ta thiết lập dự đoán khoảng 5% số lượng log trong hệ thống là bất thường
    model = IsolationForest(contamination=0.05, random_state=42)
    
    # Huấn luyện AI học hành vi từ dữ liệu log của bạn
    model.fit(X)

    # 5. Tiến hành dự đoán bất thường
    # Kết quả trả về: 1 (Bình thường) và -1 (Bất thường / Anomaly)
    df['Anomaly_Score'] = model.predict(X)

    # 6. Trích xuất xuất ra các log bị gắn nhãn là hành vi bất thường (-1)
    anomalies = df[df['Anomaly_Score'] == -1]

    # 7. Hiển thị kết quả đánh giá của AI
    print("\n" + "="*20 + " KẾT QUẢ PHÂN TÍCH AI " + "="*20)
    print(f"[+] Tổng số log kiểm tra: {len(df)}")
    print(f"[🚨] Phát hiện hành vi bất thường: {len(anomalies)} dòng log.")
    print("="*62)

    if not anomalies.empty:
        print("\nDanh sách chi tiết các dòng log bị AI gắn nhãn cảnh báo nguy hiểm:")
        # Chỉ in ra các cột quan trọng cho dễ nhìn
        print(anomalies[['Time', 'EventID', 'Log_Length', 'Suspicious_Keywords']])
    else:
        print("\n[✔] Hệ thống an toàn! Chưa phát hiện hành vi dị biệt nào.")

if __name__ == "__main__":
    train_and_detect_anomalies()