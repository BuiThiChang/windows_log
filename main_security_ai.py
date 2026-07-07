import win32evtlog
import time
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from collections import deque
import warnings
import logging

# Ẩn các cảnh báo định dạng thuộc tính để Terminal sạch sẽ
warnings.filterwarnings("ignore", category=UserWarning)

# =====================================================================
# EXPERIMENTAL HYPERPARAMETERS (Tham số cấu hình thực nghiệm)
# =====================================================================
CONTAMINATION_RATE = 0.05       # Tỷ lệ dị biệt (Anomaly Rate) dự kiến
FAILED_THRESHOLD_COUNT = 5     # Ngưỡng số lần đăng nhập sai tối đa (K)
FAILED_THRESHOLD_WINDOW = 10   # Khung cửa sổ thời gian trượt (Delta T - giây)
SCAN_INTERVAL_SECONDS = 0.5    # Tần suất quét log hệ thống
# =====================================================================

# Cấu hình hệ thống Logging phục vụ giám sát và lưu vết sự cố
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("incident_alerts.txt", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def extract_features_live(event_id, message_str, historical_counts):
    """
    Trích xuất không gian đặc trưng (Feature Extraction Engine)
    Không gian đặc trưng 5 chiều chuẩn hóa hành vi dòng dữ liệu log.
    """
    suspicious_keywords = ["failed", "denied", "error", "unauthorized", "administrator", "root"]
    message_lower = message_str.lower()
    keyword_count = sum(1 for word in suspicious_keywords if word in message_lower)
    
    freq = historical_counts.get(event_id, 0) + 1
    return [event_id, len(message_str), keyword_count, 1 if "administrator" in message_lower else 0, freq]

def run_ai_soc_system():
    logging.info("="*60)
    logging.info("   HỆ THỐNG GIÁM SÁT AI REALTIME - PHIÊN BẢN NGHIÊN CỨU KHOA HỌC")
    logging.info("="*60)
    
    features = ['EventID', 'Log_Length', 'Suspicious_Keywords', 'Is_Admin_Action', 'Event_Frequency']
    
    # Kỷ lục số liệu phục vụ đánh giá thực nghiệm (Experimental Metrics)
    metrics = {
        "Total_Processed_Logs": 0,
        "AI_Anomalies_Detected": 0,
        "Brute_Force_Alerts": 0,
        "Normal_Logs": 0,
        "Start_Time": time.time()
    }
    
    # Bộ đệm thời gian trượt lưu trữ các mốc thời gian của Event ID 4625
    failed_login_tracker = deque()
    
    # 1. Khởi tạo mô hình nền tảng và bộ chuẩn hóa đặc trưng
    ai_model = None
    scaler = None
    event_counts = {}
    
    try:
        df_history = pd.read_csv("windows_security_dataset.csv")
        event_counts = df_history['EventID'].value_counts().to_dict()
        df_history['Event_Frequency'] = df_history['EventID'].map(event_counts)
        
        # Sử dụng RobustScaler để loại bỏ ảnh hưởng của các giá trị ngoại lai trong tập huấn luyện
        scaler = RobustScaler()
        X_train_scaled = scaler.fit_transform(df_history[features])
        
        ai_model = IsolationForest(contamination=CONTAMINATION_RATE, random_state=42)
        ai_model.fit(X_train_scaled)
        logging.info("[✔] Khởi tạo AI và RobustScaler hoàn tất.")
    except Exception as e:
        logging.warning(f"[!] Chạy chế độ Online Learning không có mô hình nền tảng do lỗi: {e}")

    # 2. Cấu hình kết nối Windows Event Log
    server = 'localhost'
    log_type = 'Security'
    
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        logging.critical(f"[❌] Lỗi phân quyền hệ thống. Cần chạy Python bằng quyền Administrator! Chi tiết: {e}")
        return
    
    # Định vị con trỏ hệ thống (Log Pointer Alignment) về mốc thời gian hiện tại
    total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
    oldest_record = win32evtlog.GetOldestEventLogRecord(hand)
    last_record_offset = oldest_record + total_records - 1
    
    logging.info(f"[✔] Tổng số log lịch sử hiện tại: {total_records}")
    logging.info("[👉] Đang dịch chuyển con trỏ tới cuối dòng sự kiện để bắt log realtime...")
    logging.info("-" * 60)

    if total_records > 0:
        try:
            win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ, last_record_offset)
        except Exception as e:
            logging.error(f"[!] Lỗi đồng bộ con trỏ log: {e}")

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    try:
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if events:
                for event in events:
                    try:
                        metrics["Total_Processed_Logs"] += 1
                        
                        event_id = event.EventID & 0xFFFF
                        time_generated = event.TimeGenerated.Format()
                        data = event.StringInserts
                        message_str = ", ".join(data) if data else "No detail data"
                        
                        # Trích xuất vector đặc trưng động
                        log_vector = extract_features_live(event_id, message_str, event_counts)
                        event_counts[event_id] = event_counts.get(event_id, 0) + 1
                        
                        # Dự đoán dị biệt qua mô hình AI (nếu có)
                        prediction = 1  # Mặc định là bình thường
                        if ai_model is not None and scaler is not None:
                            X_live = pd.DataFrame([log_vector], columns=features)
                            X_live_scaled = scaler.transform(X_live)  # Chuẩn hóa vector đầu vào đồng bộ với mô hình
                            prediction = ai_model.predict(X_live_scaled)[0]
                        
                        current_time = time.time()
                        
                        # 3. Hybrid Decision Layer (Tầng ra quyết định kết hợp)
                        if event_id == 4625:
                            failed_login_tracker.append(current_time)
                        
                        # Loại bỏ các mốc thời gian cũ vượt quá kích thước cửa sổ Delta T nhằm tối ưu bộ nhớ
                        while failed_login_tracker and (current_time - failed_login_tracker[0] > FAILED_THRESHOLD_WINDOW):
                            failed_login_tracker.popleft()
                            
                        recent_failures = len(failed_login_tracker)
                        
                        # Tiêu chí phân loại cảnh báo
                        if prediction == -1:
                            metrics["AI_Anomalies_Detected"] += 1
                            alert_msg = f"[🚨 AI ANOMALY] {time_generated} | ID: {event_id} -> Phát hiện dị biệt mô hình! | Vector: {log_vector}"
                            logging.warning(alert_msg)
                            
                        elif event_id == 4625 and recent_failures >= FAILED_THRESHOLD_COUNT:
                            metrics["Brute_Force_Alerts"] += 1
                            alert_msg = f"[🚨 BRUTE FORCE] {time_generated} | Tần suất vượt ngưỡng an toàn: {recent_failures} lần lỗi trong {FAILED_THRESHOLD_WINDOW} giây!"
                            logging.warning(alert_msg)
                            
                        else:
                            metrics["Normal_Logs"] += 1
                            # Log thông thường ghi nhận ở mức độ thấp (Dùng để đếm dữ liệu)
                            logging.info(f"[✔ Bình thường] {time_generated} | Event ID: {event_id}")
                            
                    except Exception as event_error:
                        logging.error(f"[!] Lỗi xử lý bản ghi đơn lẻ: {event_error}")
            
            time.sleep(SCAN_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        # 4. Xuất số liệu thực nghiệm (Experimental Evaluation Output)
        end_time = time.time()
        duration = round(end_time - metrics["Start_Time"], 2)
        
        logging.info("\n" + "="*60)
        logging.info("   ĐÃ DỪNG HỆ THỐNG - ĐANG XUẤT SỐ LIỆU THỰC NGHIỆM")
        logging.info("="*60)
        
        report_data = {
            "Metric_Name": [
                "Tổng thời gian thực nghiệm (giây)", 
                "Tổng số log đã xử lý", 
                "Số cảnh báo dị biệt từ AI", 
                "Số cảnh báo Brute Force từ bộ lọc tần suất", 
                "Số log an toàn"
            ],
            "Value": [
                duration, 
                metrics["Total_Processed_Logs"], 
                metrics["AI_Anomalies_Detected"], 
                metrics["Brute_Force_Alerts"], 
                metrics["Normal_Logs"]
            ]
        }
        
        df_report = pd.DataFrame(report_data)
        output_file = "experimental_results.csv"
        df_report.to_csv(output_file, index=False, encoding="utf-8-sig")
        
        print(df_report.to_string(index=False))
        logging.info(f"\n[✔] Số liệu thực nghiệm đã được xuất thành công ra file: '{output_file}'")
        
    finally:
        win32evtlog.CloseEventLog(hand)

if __name__ == "__main__":
    run_ai_soc_system()
