import win32evtlog
import time
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import warnings

# Ẩn các cảnh báo định dạng thuộc tính để Terminal sạch sẽ
warnings.filterwarnings("ignore", category=UserWarning)

def extract_features_live(event_id, message_str, historical_counts):
    """Trích xuất đặc trưng realtime dựa trên tần suất"""
    suspicious_keywords = ["failed", "denied", "error", "unauthorized", "administrator", "root"]
    message_lower = message_str.lower()
    keyword_count = sum(1 for word in suspicious_keywords if word in message_lower)
    
    freq = historical_counts.get(event_id, 0) + 1
    return [event_id, len(message_str), keyword_count, 1 if "administrator" in message_lower else 0, freq]

def run_ai_soc_system():
    print("="*60)
    print("   HỆ THỐNG GIÁM SÁT AI REALTIME (CHỈ LẮNG NGHE SỰ KIỆN MỚI)")
    print("="*60)
    
    features = ['EventID', 'Log_Length', 'Suspicious_Keywords', 'Is_Admin_Action', 'Event_Frequency']
    
    # 1. Khởi tạo mô hình nền tảng
    try:
        df_history = pd.read_csv("windows_security_dataset.csv")
        event_counts = df_history['EventID'].value_counts().to_dict()
        df_history['Event_Frequency'] = df_history['EventID'].map(event_counts)
        
        ai_model = IsolationForest(contamination=0.05, random_state=42)
        ai_model.fit(df_history[features])
        print("[✔] Khởi tạo AI hoàn tất.")
    except Exception:
        print("[!] Chạy chế độ học trực tiếp (Online Learning).")
        ai_model = None
        event_counts = {}

    # 2. Cấu hình kết nối Windows Event Log
    server = 'localhost'
    log_type = 'Security'
    hand = win32evtlog.OpenEventLog(server, log_type)
    
    # Đếm số lượng log hiện tại đang có sẵn trong máy tính
    total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
    print(f"[✔] Hiện tại hệ thống đang có sẵn {total_records} log lịch sử.")
    print("[👉] Đang nhảy tới cuối dòng sự kiện để đợi các log mới tinh...")
    print("-" * 60)

    # Đọc thử một bản ghi ngược từ cuối để dịch con trỏ hệ thống về mốc thời gian HIỆN TẠI
    win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)

    # Cấu hình Flag: Chỉ đọc tuần tự tiến về phía trước (Xuôi theo thời gian)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    try:
        while True:
            # Đọc các sự kiện mới sinh ra kể từ vị trí con trỏ hiện tại
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if events:
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    time_generated = event.TimeGenerated.Format()
                    data = event.StringInserts
                    message_str = ", ".join(data) if data else "No detail data"
                    
                    # Trích xuất và dự đoán
                    log_vector = extract_features_live(event_id, message_str, event_counts)
                    event_counts[event_id] = event_counts.get(event_id, 0) + 1
                    
                    if ai_model is not None:
                        X_live = pd.DataFrame([log_vector], columns=features)
                        prediction = ai_model.predict(X_live)[0]
                    else:
                        prediction = 1
                    
                    # Đưa ra cảnh báo sự cố thời gian thực
                    if prediction == -1 or event_id == 4625:
                        alert_msg = f"[🚨 CẢNH BÁO BẤT THƯỜNG] {time_generated} | Event ID: {event_id} -> Hành vi dị biệt dồn dập!"
                        print(alert_msg)
                        
                        with open("incident_alerts.txt", "a", encoding="utf-8") as alert_file:
                            alert_file.write(f"[{time_generated}] REALTIME ALERT - EventID: {event_id} | Vector: {log_vector}\n")
                    else:
                        print(f"[✔ Bình thường] {time_generated} | Event ID: {event_id}")
            
            # Nghỉ 0.5 giây mỗi chu kỳ quét để vừa đảm bảo realtime, vừa nhẹ CPU
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[!] Đã dừng hệ thống giám sát Realtime.")

if __name__ == "__main__":
    run_ai_soc_system()