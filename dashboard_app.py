import streamlit as st
import pandas as pd
import numpy as np
import win32evtlog
from sklearn.ensemble import IsolationForest
import warnings
from datetime import datetime, date
import plotly.express as px

warnings.filterwarnings("ignore", category=UserWarning)

# --- CẤU HÌNH GIAO DIỆN STREAMLIT ---
st.set_page_config(page_title="AI SOC - Advanced Monitor", layout="wide")
st.title("🛡️ HỆ THỐNG SOC GIÁM SÁT & PHÁT HIỆN BẤT THƯỜNG LOG AI")
st.markdown("---")

# --- KHỞI TẠO SESSION STATE ---
if "chart_data" not in st.session_state:
    st.session_state.chart_data = pd.DataFrame(columns=["Timestamp", "Count"])
if "alert_list" not in st.session_state:
    st.session_state.alert_list = []
if "event_counts" not in st.session_state:
    st.session_state.event_counts = {}
if "initialized" not in st.session_state:
    st.session_state.initialized = False

# --- HÀM TỰ ĐỘNG CÀO DỮ LIỆU THẬT ---
def auto_fetch_historical_logs(output_file="windows_security_dataset.csv", max_records=4000):
    server = 'localhost'
    log_type = 'Security'
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        log_list = []
        suspicious_keywords = ["failed", "denied", "error", "unauthorized", "administrator", "root", "cleared"]
        
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events or len(log_list) >= max_records:
                break
            for event in events:
                if len(log_list) >= max_records:
                    break
                event_id = event.EventID & 0xFFFF
                data = event.StringInserts
                msg = ", ".join(data) if data else ""
                
                # Xử lý thời gian lịch sử
                time_str = event.TimeGenerated.Format('%Y-%m-%d %H:%M:%S')
                t_obj = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                
                log_list.append({
                    "Timestamp": time_str,
                    "EventID": event_id,
                    "Log_Length": len(msg),
                    "Suspicious_Keywords": sum(1 for w in suspicious_keywords if w in msg.lower()),
                    "Is_Admin_Action": 1 if ("administrator" in msg.lower() or "system" in msg.lower()) else 0,
                    "Is_Off_Hours": 1 if (t_obj.hour >= 22 or t_obj.hour < 5) else 0,
                    "Is_Critical_Event": 1 if event_id in [1102, 4672] else 0
                })
        
        if log_list:
            df = pd.DataFrame(log_list).iloc[::-1].reset_index(drop=True)
            df['Event_Frequency'] = df.groupby('EventID').cumcount() + 1
            df.to_csv(output_file, index=False)
    except Exception:
        pass
# --- ĐỌC DỮ LIỆU LỊCH SỬ TRƯỚC VÀ HUẤN LUYỆN AI ---
# ĐÃ CẬP NHẬT: Mở rộng bộ đặc trưng để AI học được nhiều kịch bản tấn công hơn
features = [
    'EventID', 
    'Log_Length', 
    'Suspicious_Keywords', 
    'Is_Admin_Action', 
    'Event_Frequency',
    'Is_Off_Hours',      # 1 nếu đăng nhập từ 22h đêm - 5h sáng, 0 nếu giờ hành chính
    'Is_Critical_Event'  # 1 nếu là Event phá hoại xóa log (1102) hoặc leo thang quyền (4672)
]

@st.cache_resource
def load_history_and_model():
    auto_fetch_historical_logs(max_records=4000)
    file_path = "windows_security_dataset.csv"
    try:
        df_history = pd.read_csv(file_path)
        df_history['Timestamp'] = pd.to_datetime(df_history['Timestamp'])
        evt_counts = df_history['EventID'].value_counts().to_dict()
        
        ai_model = IsolationForest(contamination=0.05, random_state=42)
        ai_model.fit(df_history[features])
        return df_history, ai_model, evt_counts, True
    except Exception:
        return None, None, {}, False

df_history, ai_model, historical_counts, history_loaded = load_history_and_model()

if history_loaded and not st.session_state.initialized:
    st.session_state.event_counts.update(historical_counts)
    st.session_state.initialized = True
# --- THANH SIDEBAR CẤU HÌNH (CẬP NHẬT THEO CÁC MỐC THỜI GIAN QUAY NGƯỢC) ---
st.sidebar.header("⚙️ CẤU HÌNH GIÁM SÁT")
time_window = st.sidebar.selectbox(
    "⏱️ Khung thời gian Live:",
    [
        "5 giây trước đến nay",
        "10 giây trước đến nay",
        "5 phút trước đến nay",
        "10 phút trước đến nay",
        "30 phút trước đến nay",
        "1 giờ trước đến nay",
        "6 giờ trước đến nay",
        "12 giờ trước đến nay",
        "24 giờ trước đến nay"
    ]
)
st.sidebar.markdown("---")

# --- PHÂN CHIA TAB CỦA ỨNG DỤNG ---
tab_live, tab_history, tab_report = st.tabs([
    "🔴 Giám sát Realtime", 
    "📂 Thống kê Lịch sử (Tổng quan)", 
    "📋 Báo cáo Cảnh báo"
])

# --- HÀM TRÍCH XUẤT ĐẶC TRƯNG LIVE ---
def extract_features_live(event_id, message_str, counts_dict, timestamp_obj=None):
    """
    Trích xuất cấu trúc vector đặc trưng mở rộng (7 chiều) phục vụ AI phát hiện đa kịch bản
    """
    if timestamp_obj is None:
        timestamp_obj = datetime.now()
        
    # 1. Từ khóa nghi vấn
    suspicious_keywords = ["failed", "denied", "error", "unauthorized", "administrator", "root", "cleared"]
    message_lower = message_str.lower()
    keyword_count = sum(1 for word in suspicious_keywords if word in message_lower)
    
    # 2. Tần suất xuất hiện mã sự kiện
    freq = counts_dict.get(event_id, 0) + 1
    
    # 3. Kiểm tra hành động liên quan Admin
    is_admin = 1 if "administrator" in message_lower or "system" in message_lower else 0
    
    # 4. KỊCH BẢN 1: Đăng nhập ngoài giờ hành chính (Off-Hours từ 22h đêm đến 5h sáng)
    is_off_hours = 1 if (timestamp_obj.hour >= 22 or timestamp_obj.hour < 5) else 0
    
    # 5. KỊCH BẢN 2 & 3: Sự kiện trọng yếu cần báo động (1102: Xóa log, 4672: Quyền tối cao)
    is_critical = 1 if event_id in [1102, 4672] else 0
    
    # Trả về đúng cấu trúc vector 7 chiều tương thích với mô hình AI
    return [event_id, len(message_str), keyword_count, is_admin, freq, is_off_hours, is_critical]

# --- KẾT NỐI WINDOWS LOG REALTIME ---
@st.cache_resource
def open_windows_log_live():
    server = 'localhost'
    log_type = 'Security'
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        return hand
    except Exception as e:
        st.error(f"❌ Hãy chạy CMD bằng quyền Administrator! Lỗi: {e}")
        st.stop()

hand = open_windows_log_live()
flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

# ================= TAB 1: GIÁM SÁT REALTIME (BẢN CHUẨN: TRÊN - DƯỚI & QUÉT AI QUÁ KHỨ) =================
with tab_live:
    # --- PHẦN TRÊN: BIỂU ĐỒ CHIẾM TOÀN BỘ CHIỀU RỘNG MÀN HÌNH ---
    st.subheader(f"📊 Đồ thị mật độ Log ({time_window})")
    chart_placeholder = st.empty()
    
    st.markdown("---") # Vạch kẻ ngang phân cách

    # --- PHẦN DƯỚI: NHẬT KÝ CẢNH BÁO CHIẾM TOÀN BỘ CHIỀU RỘNG MÀN HÌNH ---
    st.subheader("🚨 Nhật ký Cảnh báo Hành vi Bất thường")
    table_placeholder = st.empty()

    # --- 1. ĐỒNG BỘ DỮ LIỆU NỀN (QUÉT CẢ SỐ LƯỢNG LẪN CẢNH BÁO CỦA 30 PHÚT TRƯỚC) ---
    if st.session_state.chart_data.empty:
        with st.spinner("🔄 Đang phân tích AI và đồng bộ dòng thời gian Realtime từ Windows..."):
            h_hand = win32evtlog.OpenEventLog('localhost', 'Security')
            h_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            past_records = []
            max_init_logs = 1500  # Quét đủ sâu để gom cảnh báo cũ trong quá khứ gần
            
            while True:
                h_events = win32evtlog.ReadEventLog(h_hand, h_flags, 0)
                if not h_events or len(past_records) >= max_init_logs:
                    break
                for ev in h_events:
                    if len(past_records) >= max_init_logs:
                        break
                    
                    # Trích xuất thời gian làm dữ liệu vẽ biểu đồ
                    t_gen = datetime.strptime(ev.TimeGenerated.Format('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
                    past_records.append(t_gen)
                    
                    # Đưa log cũ này qua AI để tìm kiếm các cảnh báo ẩn trong quá khứ gần
                    event_id = ev.EventID & 0xFFFF
                    data = ev.StringInserts
                    message_str = ", ".join(data) if data else "No detail data"
                    
                    log_vector = extract_features_live(event_id, message_str, st.session_state.event_counts)
                    st.session_state.event_counts[event_id] = st.session_state.event_counts.get(event_id, 0) + 1
                    
                    if ai_model is not None:
                        X_past = pd.DataFrame([log_vector], columns=features)
                        prediction = ai_model.predict(X_past)[0]
                    else:
                        prediction = 1
                        
                    # Định nghĩa luật cứng cho các kịch bản tấn công nguy hiểm
                    is_brute_force = (event_id == 4625)
                    is_clear_logs = (event_id == 1102)
                    is_privilege_escalation = (event_id == 4672)
                    # ĐÃ SỬA: Thay "now.hour" bằng "t_gen.hour"
                    is_stealthy_login = (event_id == 4624 and (t_gen.hour >= 22 or t_gen.hour < 5))

                    # Kích hoạt cảnh báo nếu AI chấm điểm bất thường HOẶC dính bất kỳ kịch bản nguy hiểm nào ở trên
                    if prediction == -1 or is_brute_force or is_clear_logs or is_privilege_escalation or is_stealthy_login:
                        if not any(a['Thời gian'] == ev.TimeGenerated.Format() and a['Event ID'] == event_id for a in st.session_state.alert_list):
                            st.session_state.alert_list.append({
                                "Thời gian": ev.TimeGenerated.Format(),
                                "Ngày": t_gen.date(),
                                "Event ID": event_id,
                                "Mức độ": "🚨 NGUY HIỂM",
                                "Chi tiết": f"Phát hiện hành vi dị biệt trong quá khứ gần. Vector: {log_vector}"
                            })
            
            if past_records:
                df_past = pd.DataFrame(past_records, columns=["Timestamp"])
                df_counts = df_past.groupby("Timestamp").size().reset_index(name="Count")
                st.session_state.chart_data = df_counts

    # --- 2. FRAGMENT CẬP NHẬT REALTIME MỖI GIÂY (DÒNG CHẢY LOG MỚI) ---
    @st.fragment(run_every=1.0)
    def update_live_data():
        now = datetime.now()
        log_count_this_second = 0
        try:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        except Exception:
            events = []
        
        if events:
            log_count_this_second = len(events)
            for event in events:
                event_id = event.EventID & 0xFFFF
                time_generated = event.TimeGenerated.Format()
                data = event.StringInserts
                message_str = ", ".join(data) if data else "No detail data"
                
                log_vector = extract_features_live(event_id, message_str, st.session_state.event_counts)
                st.session_state.event_counts[event_id] = st.session_state.event_counts.get(event_id, 0) + 1
                
                if ai_model is not None:
                    X_live = pd.DataFrame([log_vector], columns=features)
                    prediction = ai_model.predict(X_live)[0]
                else:
                    prediction = 1
                    
                if prediction == -1 or event_id == 4625:
                    st.session_state.alert_list.insert(0, {
                        "Thời gian": time_generated,
                        "Ngày": now.date(),
                        "Event ID": event_id,
                        "Mức độ": "🚨 NGUY HIỂM",
                        "Chi tiết": f"Hành vi dị biệt realtime. Vector đặc trưng: {log_vector}"
                    })

        # Lưu log mới vào bộ nhớ
        new_log_record = pd.DataFrame([{"Timestamp": now.replace(microsecond=0), "Count": log_count_this_second}])
        st.session_state.chart_data = pd.concat([st.session_state.chart_data, new_log_record], ignore_index=True)

        # Trích xuất và lọc dữ liệu trượt theo thời gian chọn trên Sidebar
        df_temp = st.session_state.chart_data.copy()
        df_temp["Timestamp"] = pd.to_datetime(df_temp["Timestamp"])

        if "5 giây" in time_window:
            start_cutoff = now - pd.Timedelta(seconds=5)

        elif "10 giây" in time_window:
            start_cutoff = now - pd.Timedelta(seconds=10)

        elif "5 phút" in time_window:
            start_cutoff = now - pd.Timedelta(minutes=5)

        elif "10 phút" in time_window:
            start_cutoff = now - pd.Timedelta(minutes=10)

        elif "30 phút" in time_window:
            start_cutoff = now - pd.Timedelta(minutes=30)

        elif "1 giờ" in time_window:
            start_cutoff = now - pd.Timedelta(hours=1)

        elif "6 giờ" in time_window:
            start_cutoff = now - pd.Timedelta(hours=6)

        elif "12 giờ" in time_window:
            start_cutoff = now - pd.Timedelta(hours=12)

        elif "24 giờ" in time_window:
            start_cutoff = now - pd.Timedelta(hours=24)

        df_filtered_live = df_temp[df_temp["Timestamp"] >= start_cutoff]

        # Định dạng trục X hiển thị
        if "giây" in time_window or "phút" in time_window:
            df_filtered_live["Thời gian"] = df_filtered_live["Timestamp"].dt.strftime("%H:%M:%S")
        else:
            df_filtered_live["Thời gian"] = df_filtered_live["Timestamp"].dt.strftime("%H:%M")

        df_chart = df_filtered_live.groupby("Thời gian")["Count"].sum().reset_index(name="Số lượng Log")

        # Vẽ biểu đồ Line Chart căng tràn màn hình
        if not df_chart.empty:
            chart_placeholder.line_chart(df_chart.set_index("Thời gian"), use_container_width=True)
        else:
            chart_placeholder.info("Đang chờ đồng bộ dữ liệu trong khung thời gian yêu cầu...")
        
        # Cập nhật danh sách cảnh báo (Cảnh báo cũ + Cảnh báo mới sẽ hiển thị toàn bộ ở đây)
        if st.session_state.alert_list:
            df_display = pd.DataFrame(st.session_state.alert_list).drop(columns=["Ngày"], errors="ignore")
            table_placeholder.dataframe(df_display.style.set_properties(**{'background-color': '#ffcccc', 'color': 'black'}), use_container_width=True)
        else:
            table_placeholder.info("Chưa phát hiện hành vi bất thường nào. Hệ thống an toàn.")

    update_live_data()

# ================= TAB 2: THỐNG KÊ LỊCH SỬ (BẢN CHUẨN) =================
with tab_history:
    st.subheader("📊 Phân tích Cơ sở Dữ liệu Log thật theo Khoảng thời gian")
    
    if history_loaded:
        # Lấy ngày nhỏ nhất và lớn nhất có trong tập dữ liệu thật để đặt làm mặc định
        min_date = df_history['Timestamp'].min().date()
        max_date = df_history['Timestamp'].max().date()
        
        # --- BỘ LỌC KHOẢNG THỜI GIAN ---
        st.markdown("#### 📅 Bộ lọc khoảng thời gian điều tra:")
        col_date_1, col_date_2 = st.columns(2)
        
        with col_date_1:
            start_date = st.date_input("Từ ngày:", min_date, min_value=min_date, max_value=max_date, key="hist_start")
        with col_date_2:
            end_date = st.date_input("Đến ngày:", max_date, min_value=min_date, max_value=max_date, key="hist_end")
            
        if start_date > end_date:
            st.error("❌ Lỗi: Ngày bắt đầu không thể lớn hơn ngày kết thúc!")
        else:
            # Tiến hành lọc dữ liệu theo khoảng thời gian người dùng chọn
            mask = (df_history['Timestamp'].dt.date >= start_date) & (df_history['Timestamp'].dt.date <= end_date)
            df_filtered = df_history.loc[mask]
            
            st.info(f"📋 Tìm thấy **{len(df_filtered)}** log bảo mật trong khoảng thời gian từ `{start_date}` đến `{end_date}`.")
            st.markdown("---")
            
            # --- CÁC TIÊU CHÍ THỐNG KÊ BIỂU ĐỒ ---
            col_hist_1, col_hist_2 = st.columns(2)
            with col_hist_1:
                hist_metric = st.selectbox(
                    "Chọn tiêu chí phân tích đồ thị:",
                    ["Số lượng theo Event ID", "Độ dài Log trung bình theo Event ID", "Tần suất từ khóa nghi vấn"],
                    key="hist_metric_select"
                )
            with col_hist_2:
                top_n = st.slider("Số lượng Event ID hiển thị tối đa:", 5, 30, 10, key="top_n_slider")
                
            st.markdown("#### Đồ thị phân tích dữ liệu cũ")
            
            if len(df_filtered) > 0:
                
                df_chart_data = None
                y_axis_title = ""
                chart_title = ""
                
                if hist_metric == "Số lượng theo Event ID":
                    df_chart_data = df_filtered['EventID'].value_counts().reset_index(name='Số lượng log').head(top_n)
                    y_axis_title = "Số lượng Log (Bản ghi)"
                    chart_title = "Thống kê tổng số lượng Log theo Event ID"
                    
                elif hist_metric == "Độ dài Log trung bình theo Event ID":
                    df_chart_data = df_filtered.groupby('EventID')['Log_Length'].mean().reset_index(name='Độ dài trung bình').head(top_n)
                    y_axis_title = "Độ dài ký tự trung bình"
                    chart_title = "Độ dài Log trung bình của từng Event ID"
                    
                elif hist_metric == "Tần suất từ khóa nghi vấn":
                    df_chart_data = df_filtered.groupby('EventID')['Suspicious_Keywords'].sum().reset_index(name='Tổng số từ khóa nguy hiểm').head(top_n)
                    y_axis_title = "Tổng số từ khóa phát hiện"
                    chart_title = "Tổng số từ khóa nghi vấn xuất hiện theo Event ID"

                if df_chart_data is not None and not df_chart_data.empty:
                    df_chart_data['EventID'] = df_chart_data['EventID'].astype(str)
                    y_col = df_chart_data.columns[1]

                    # Vẽ biểu đồ tương tác hiển thị thông số rõ ràng trên đầu cột
                    fig = px.bar(
                        df_chart_data, 
                        x='EventID', 
                        y=y_col,
                        title=chart_title,
                        labels={'EventID': 'Mã sự kiện (Event ID)', y_col: y_axis_title},
                        color=y_col,
                        color_continuous_scale="Blues_r",
                        text_auto='.1f' if 'trung bình' in y_col else True
                    )

                    fig.update_layout(xaxis={'type': 'category'}, showlegend=False, coloraxis_showscale=False)
                    fig.update_traces(textposition='outside')

                    # Hiển thị biểu đồ Plotly
                    st.plotly_chart(fig, use_container_width=True)
                
                # --- ĐƯA BẢNG DỮ LIỆU THÔ RA NGOÀI HIỂN THỊ TRỰC TIẾP ---
                st.markdown("---")
                st.markdown("### 🔍 Bảng dữ liệu chi tiết của khoảng thời gian này (Raw Data)")
                st.dataframe(df_filtered, use_container_width=True)
                
            else:
                st.warning("⚠️ Không có dữ liệu log nào trong khoảng thời gian bạn đã chọn.")
    else:
        st.error("❌ Không thể kết nối hoặc khởi tạo dữ liệu log lịch sử.")

# ================= TAB 3: 📋 BÁO CÁO CẢNH BÁO BẤT THƯỜNG (BẢN ĐẦY ĐỦ QUÁ KHỨ) =================
with tab_report:
    st.subheader("📋 Phân tích & Xuất Báo cáo Hành vi Bất thường (Toàn bộ dữ liệu)")
    st.markdown("Trang này tự động lọc riêng các sự kiện có dấu hiệu nguy hiểm hoặc dị biệt từ **cơ sở dữ liệu lịch sử** và **quá trình giám sát live**.")

    if history_loaded and df_history is not None:
        # --- 1. SÀNG LỌC TOÀN BỘ CẢNH BÁO TỪ QUÁ KHỨ ĐẾN HIỆN TẠI ---
        # Sử dụng mô hình AI dự đoán lại trên tập dữ liệu lịch sử để tìm các điểm dị biệt (-1)
        with st.spinner("🔄 Đang đồng bộ và phân tích các dấu hiệu bất thường trong quá khứ..."):
            df_hist_copy = df_history.copy()
            if ai_model is not None:
                df_hist_copy['Prediction'] = ai_model.predict(df_hist_copy[features])
            else:
                df_hist_copy['Prediction'] = 1
            
            # Lọc log quá khứ: Hoặc là AI báo bất thường (-1), hoặc là lỗi Log fail (4625)
            df_hist_anomalies = df_hist_copy[(df_hist_copy['Prediction'] == -1) | (df_hist_copy['EventID'] == 4625)].copy()
            
            # Chuẩn hóa các cột để chuẩn bị gộp với dữ liệu Realtime
            df_hist_anomalies['Mức độ'] = "🚨 NGUY HIỂM"
            df_hist_anomalies['Chi tiết'] = df_hist_anomalies.apply(
                lambda r: f"Hành vi dị biệt quá khứ. Vector đặc trưng: [{int(r['EventID'])}, {int(r['Log_Length'])}, {int(r['Suspicious_Keywords'])}, {int(r['Is_Admin_Action'])}, {int(r['Event_Frequency'])}]", axis=1
            )
            df_hist_report = df_hist_anomalies[['Timestamp', 'EventID', 'Mức độ', 'Chi tiết']].rename(columns={'EventID': 'Event ID'})
            df_hist_report['Ngày'] = pd.to_datetime(df_hist_report['Timestamp']).dt.date

        # Lấy thêm các cảnh báo realtime thu thập được từ lúc bật app (nếu có)
        if st.session_state.alert_list:
            df_live_report = pd.DataFrame(st.session_state.alert_list)
            df_live_report['Timestamp'] = pd.to_datetime(df_live_report['Thời gian'])
            df_live_report = df_live_report[['Timestamp', 'Event ID', 'Mức độ', 'Chi tiết', 'Ngày']]
            
            # Gộp chung Quá khứ + Realtime thành một kho cảnh báo duy nhất
            df_all_alerts = pd.concat([df_live_report, df_hist_report], ignore_index=True)
        else:
            df_all_alerts = df_hist_report

        # Loại bỏ các dòng trùng lặp nếu có và sắp xếp theo thời gian mới nhất lên đầu
        df_all_alerts = df_all_alerts.drop_duplicates(subset=['Timestamp', 'Event ID']).sort_values(by='Timestamp', ascending=False)

        # --- 2. BỘ LỌC THỜI GIAN THEO NGÀY (GIỐNG TAB 2) ---
        min_report_date = pd.to_datetime(df_all_alerts['Timestamp']).min().date()
        max_report_date = pd.to_datetime(df_all_alerts['Timestamp']).max().date()

        st.markdown("---")
        st.markdown("#### 📅 Bộ lọc khoảng thời gian điều tra sự cố:")
        col_rep_d1, col_rep_d2 = st.columns(2)
        with col_rep_d1:
            rep_start = st.date_input("Báo cáo từ ngày:", min_report_date, min_value=min_report_date, max_value=max_report_date, key="rep_start")
        with col_rep_d2:
            rep_end = st.date_input("Báo cáo đến ngày:", max_report_date, min_value=min_report_date, max_value=max_report_date, key="rep_end")

        if rep_start > rep_end:
            st.error("❌ Lỗi: Ngày bắt đầu không thể lớn hơn ngày kết thúc!")
        else:
            # Lọc dữ liệu cảnh báo tổng hợp theo khoảng ngày đã chọn
            mask_alert = (df_all_alerts['Ngày'] >= rep_start) & (df_all_alerts['Ngày'] <= rep_end)
            df_report_filtered = df_all_alerts.loc[mask_alert]

            if not df_report_filtered.empty:
                # --- 3. THỐNG KÊ NHANH CHỈ SỐ KPI BÁO CÁO ---
                st.markdown("### 📈 Thống kê nhanh chỉ số an toàn hệ thống")
                c1, c2, c3 = st.columns(3)
                c1.metric("Tổng số cảnh báo phát hiện", f"{len(df_report_filtered)} vụ")
                c2.metric("Số lượng Event 4625 (Login Fail)", f"{len(df_report_filtered[df_report_filtered['Event ID'] == 4625])} vụ")
                
                top_attack_id = df_report_filtered['Event ID'].mode()[0] if not df_report_filtered.empty else "N/A"
                c3.metric("Mã sự kiện (Event ID) rủi ro nhất", str(top_attack_id))

                # --- 4. BIỂU ĐỒ THỐNG KÊ RIÊNG CHO CÁC CẢNH BÁO ---
                st.markdown("#### 📊 Đồ thị phân phối các loại Cảnh báo Nguy hiểm")
                df_alert_chart = df_report_filtered['Event ID'].value_counts().reset_index(name='Số lượng')
                df_alert_chart['Event ID'] = df_alert_chart['Event ID'].astype(str)
                
                import plotly.express as px
                fig_alert = px.bar(
                    df_alert_chart, 
                    x='Event ID', 
                    y='Số lượng',
                    title="Số lượng cảnh báo phân theo loại Event ID",
                    labels={'Event ID': 'Mã sự kiện nguy hiểm (Event ID)', 'Số lượng': 'Số lần xuất hiện'},
                    color='Số lượng',
                    color_continuous_scale="Reds", # Sử dụng dải màu đỏ cảnh báo nguy hiểm
                    text_auto=True
                )
                fig_alert.update_layout(xaxis={'type': 'category'}, showlegend=False, coloraxis_showscale=False)
                fig_alert.update_traces(textposition='outside')
                st.plotly_chart(fig_alert, use_container_width=True)

                # --- 5. HIỂN THỊ BẢNG DỮ LIỆU CHI TIẾT ---
                st.markdown("### 📝 Danh sách chi tiết các sự kiện bất thường")
                
                # Định dạng lại cột Timestamp về dạng chuỗi để hiển thị đẹp mắt
                df_display = df_report_filtered.copy()
                df_display['Timestamp'] = df_display['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_display = df_display.drop(columns=["Ngày"], errors="ignore")
                
                st.dataframe(
                    df_display.style.set_properties(
                        **{'background-color': '#fff0f0', 'color': '#b30000', 'border-color': 'red'}
                    ), 
                    use_container_width=True
                )

                # --- 6. CHỨC NĂNG XUẤT FILE BÁO CÁO CSV ---
                st.markdown("### 💾 Xuất báo cáo sự cố")
                csv_data = df_report_filtered.drop(columns=["Ngày"], errors="ignore").to_csv(index=False).encode('utf-8-sig')
                
                st.download_button(
                    label="📥 Tải xuống Toàn bộ Báo cáo Cảnh báo (.CSV)",
                    data=csv_data,
                    file_name=f"SOC_Full_Anomaly_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    help="Bấm vào đây để tải file CSV chứa tất cả các cảnh báo phục vụ lưu trữ."
                )
            else:
                st.info(f"💡 Hệ thống an toàn! Không ghi nhận bất kỳ cảnh báo bất thường nào trong khoảng từ ngày `{rep_start}` đến `{rep_end}`.")
    else:
        st.error("❌ Không thể kết nối cơ sở dữ liệu lịch sử để lọc báo cáo.")
    st.subheader("📋 Phân tích & Xuất Báo cáo Hành vi Bất thường (Anomalies Report)")
    st.markdown("Trang này tổng hợp riêng các sự kiện có dấu hiệu nguy hiểm hoặc dị biệt được phát hiện từ lúc hệ thống chạy.")
    
    if st.session_state.alert_list:
        df_all_alerts = pd.DataFrame(st.session_state.alert_list)
        
        # Thiết lập bộ lọc thời gian riêng cho báo cáo
        st.markdown("#### 🔍 Bộ lọc ngày báo cáo:")
        col_rep_d1, col_rep_d2 = st.columns(2)
        with col_rep_d1:
            # ĐÃ ĐỔI: key="rep_start_final"
            rep_start = st.date_input("Báo cáo từ ngày:", min_report_date, min_value=min_report_date, max_value=max_report_date, key="rep_start_final")
        with col_rep_d2:
            # ĐÃ ĐỔI: key="rep_end_final"
            rep_end = st.date_input("Báo cáo đến ngày:", max_report_date, min_value=min_report_date, max_value=max_report_date, key="rep_end_final")
            
        # Lọc dữ liệu cảnh báo theo ngày
        mask_alert = (df_all_alerts['Ngày'] >= rep_start) & (df_all_alerts['Ngày'] <= rep_end)
        df_report_filtered = df_all_alerts.loc[mask_alert]
        
        if not df_report_filtered.empty:
            # Thống kê nhanh chỉ số báo cáo
            st.markdown("---")
            st.markdown("### 📈 Thống kê nhanh")
            c1, c2, c3 = st.columns(3)
            c1.metric("Tổng số cảnh báo", f"{len(df_report_filtered)} vụ")
            c2.metric("Số lượng Event 4625 (Login Fail)", f"{len(df_report_filtered[df_report_filtered['Event ID'] == 4625])} vụ")
            
            # Tính Event ID bị cảnh báo nhiều nhất
            top_attack_id = df_report_filtered['Event ID'].mode()[0] if not df_report_filtered.empty else "N/A"
            c3.metric("Event ID đáng ngờ nhất", str(top_attack_id))
            
            st.markdown("---")
            st.markdown("### 📝 Danh sách sự kiện nguy hiểm chi tiết")
            
            # Hiển thị bảng dữ liệu cảnh báo có màu sắc nhấn mạnh
            st.dataframe(
                df_report_filtered.drop(columns=["Ngày"], errors="ignore").style.set_properties(
                    **{'background-color': '#fff0f0', 'color': '#b30000', 'border-color': 'red'}
                ), 
                use_container_width=True
            )
            
            # --- CHỨC NĂNG XUẤT FILE CSV BÁO CÁO ---
            st.markdown("### 💾 Xuất báo cáo sự cố")
            # Chuyển DataFrame thành chuỗi CSV định dạng UTF-8 (BOM để tránh lỗi font Excel)
            csv_data = df_report_filtered.to_csv(index=False).encode('utf-8-sig')
            
            st.download_button(
                label="📥 Tải xuống Báo cáo sự cố (.CSV)",
                data=csv_data,
                file_name=f"SOC_Anomaly_Report_{datetime.now().strftime('%Y%M%d_%H%M%S')}.csv",
                mime="text/csv",
                help="Bấm vào đây để tải file CSV lưu trữ chứa danh sách toàn bộ các cảnh báo bất thường phục vụ báo cáo."
            )
        else:
            st.info("💡 Không ghi nhận cảnh báo bất thường nào trong khoảng thời gian báo cáo đã chọn.")
    else:
        st.success("✅ Hệ thống SOC chưa ghi nhận bất kỳ hành vi bất thường nào từ lúc khởi động. Chưa có dữ liệu để lập báo cáo sự cố!")