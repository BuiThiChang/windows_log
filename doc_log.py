import win32evtlog
import pandas as pd
import os

def export_windows_security_logs(output_file="windows_security_dataset.csv", max_records=5000):
    print("🔄 Đang kết nối và đọc Windows Security Log (Vui lòng chờ)...")
    server = 'localhost'
    log_type = 'Security'
    
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        # Đọc từ log mới nhất trở về trước (Backwards)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        log_list = []
        suspicious_keywords = ["failed", "denied", "error", "unauthorized", "administrator", "root"]
        
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events or len(log_list) >= max_records:
                break
                
            for event in events:
                if len(log_list) >= max_records:
                    break
                    
                event_id = event.EventID & 0xFFFF
                data = event.StringInserts
                message_str = ", ".join(data) if data else ""
                message_lower = message_str.lower()
                
                # Trích xuất các đặc trưng giống như mô hình AI yêu cầu
                log_length = len(message_str)
                keyword_count = sum(1 for word in suspicious_keywords if word in message_lower)
                is_admin = 1 if "administrator" in message_lower else 0
                
                log_list.append({
                    "EventID": event_id,
                    "Log_Length": log_length,
                    "Suspicious_Keywords": keyword_count,
                    "Is_Admin_Action": is_admin
                })
                
        if len(log_list) == 0:
            print("❌ Không tìm thấy log nào. Bạn đã chạy Command Prompt bằng quyền Administrator chưa?")
            return
            
        # Tạo DataFrame ban đầu (đang ở dạng từ Mới đến Cũ)
        df = pd.DataFrame(log_list)
        
        # SỬA LỖI LOGIC: Đảo ngược lại để dữ liệu chạy từ Cũ đến Mới (đúng trục thời gian tuyến tính)
        df = df.iloc[::-1].reset_index(drop=True)
        
        # Tính toán Tần suất tăng dần (tương thích hoàn hảo với luồng quét Realtime)
        df['Event_Frequency'] = df.groupby('EventID').cumcount() + 1
        
        # Đảm bảo thứ tự các cột khớp 100% với features của IsolationForest
        features_order = ['EventID', 'Log_Length', 'Suspicious_Keywords', 'Is_Admin_Action', 'Event_Frequency']
        df = df[features_order]
        
        # Lưu file CSV
        df.to_csv(output_file, index=False)
        print(f"🎉 Successfully Exported! Đã xuất thành công {len(df)} dòng dữ liệu thật vào file `{output_file}`.")
        
    except Exception as e:
        print(f"❌ Lỗi: {e}. Vui lòng kiểm tra quyền Administrator!")

if __name__ == "__main__":
    export_windows_security_logs()