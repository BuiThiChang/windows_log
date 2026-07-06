import win32evtlog  # Thư viện kết nối Windows Event Log API
import time
import os
import pandas as pd  # Thư viện xử lý và lưu trữ dữ liệu bảng
import define_variable  # Thư viện tự viết để định nghĩa biến toàn cục

def extract_features(event_id, time_generated, source_name, message_str):
    """
    Hàm Tiền xử lý dữ liệu (Feature Extraction):
    Chuyển hóa văn bản log thô thành các thuộc tính số/đặc trưng mà mô hình AI hiểu được.
    """
    # Một số từ khóa đáng ngờ thường xuất hiện trong hành vi bất thường/tấn công
    suspicious_keywords = ["failed", "denied", "error", "unauthorized", "administrator", "root"]
    message_lower = message_str.lower()
    
    # Đếm xem có bao nhiêu từ khóa đáng ngờ xuất hiện trong bản ghi log này
    keyword_count = sum(1 for word in suspicious_keywords if word in message_lower)
    
    # Trích xuất các thuộc tính thành một bản ghi có cấu trúc (Dictionary)
    log_features = {
        "Time": time_generated,
        "EventID": event_id,
        "Source": source_name,
        "Log_Length": len(message_str),  # Độ dài chuỗi log (bất thường thường có độ dài dị biệt)
        "Suspicious_Keywords": keyword_count,  # Số từ khóa nghi vấn
        "Is_Admin_Action": 1 if "administrator" in message_lower else 0,  # Có động chạm quyền Admin không
    }
    return log_features

def save_to_csv(log_list):
    """
    Hàm Lưu trữ dữ liệu: Chuyển đổi danh sách sang DataFrame và ghi vào file CSV.
    """
    df_new = pd.DataFrame(log_list)
    
    # Nếu file chưa tồn tại, tạo mới và ghi cả tiêu đề (Header). 
    # Nếu đã tồn tại, ghi nối tiếp (append) vào cuối file mà không ghi lại tiêu đề.
    if not os.path.exists(define_variable.CSV_FILE_PATH):
        df_new.to_csv(define_variable.CSV_FILE_PATH, index=False, mode='w', encoding='utf-8')
        print(f"\n[+] Đã tạo mới file dữ liệu: {define_variable.CSV_FILE_PATH}")
    else:
        df_new.to_csv(define_variable.CSV_FILE_PATH, index=False, mode='a', header=False, encoding='utf-8')
        print(f"\n[+] Đã lưu thêm {len(log_list)} bản ghi log mới vào dataset CSV.")

def watch_windows_logs_complete():
    server = 'localhost'
    log_type = 'Security'  # Quét phân hệ Bảo mật (Yêu cầu VS Code mở bằng quyền Admin)
    
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        print(f"[*] ĐANG GIÁM SÁT LOG [{log_type}] REALTIME...")
        print(f"[*] Dữ liệu trích xuất sẽ tự động lưu vào file: {os.path.abspath(define_variable.CSV_FILE_PATH)}")
        print("[*] Nhấn Ctrl + C để dừng ứng dụng.\n" + "="*60)
        
        buffer_logs = []  # Bộ nhớ đệm dùng để gom log lại lưu một thể, tránh việc ghi file quá nhiều gây lag
        
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if events:
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    time_generated = event.TimeGenerated.Format()
                    source_name = event.SourceName
                    
                    data = event.StringInserts
                    message_str = ", ".join(data) if data else "No detail data"
                    
                    # 1. Trích xuất đặc trưng số hóa từ log thô
                    features = extract_features(event_id, time_generated, source_name, message_str)
                    buffer_logs.append(features)
                    
                    # In kết quả realtime ra màn hình cho người dùng theo dõi trực quan
                    print(f"[{time_generated}] ID: {event_id} | Keywords: {features['Suspicious_Keywords']} | Len: {features['Log_Length']}")
                
                # 2. Cơ chế Buffer: Gom đủ từ 10 log trở lên sẽ tự động lưu vào file CSV 
                if len(buffer_logs) >= 10:
                    save_to_csv(buffer_logs)
                    buffer_logs.clear()  # Xóa bộ nhớ đệm để chuẩn bị cho đợt tiếp theo
            
            time.sleep(1)  # Quét lặp lại sau mỗi 1 giây để tiết kiệm CPU
            
    except KeyboardInterrupt:
        # Nếu người dùng bấm Ctrl + C, lưu nốt số lượng log còn dư trong bộ nhớ đệm trước khi tắt
        if buffer_logs:
            print("\n[*] Đang lưu các bản ghi cuối cùng trước khi đóng...")
            save_to_csv(buffer_logs)
        print("\n[!] Ứng dụng giám sát log đã dừng thành công.")
        
    except Exception as e:
        print(f"\n[LỖI HỆ THỐNG]: {e}")
        print("[ gợi ý ]: Hãy chắc chắn rằng bạn đã mở VS Code bằng quyền 'Run as administrator'.")