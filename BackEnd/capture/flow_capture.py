from argus_tool import argus_client
import logging
import datetime
import time
import pytz
from joblib import load
import pandas as pd
from data import database

def seconds_to_hms(seconds):
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{int(hours):02}:{int(minutes):02}:{int(secs):02}"

def run_capture(interface, duration):
    APP_NAME = "ArgusTest"

    # Tải mô hình Random Forest
    rf_model = load('my_rf_model.joblib')

    # Thiết lập logging
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # --- Khởi động Argus server ---
    """"
    started, process = argus.start_argus(
        path_to_argus='/usr/local/sbin/argus',
        interface=interface,
        server_port=561
    )

    if not started:
        logger.warning(f"The argus server is running PID = {process}.")
    else:
        while True:
            logger.info("Waiting for the argus server ...")
            time.sleep(3)
            is_running, pid = argus.is_argus_server_running()
            if is_running:
                logger.info(f"The argus server is running PID = {pid}.")
                break
    """

    # Ghi lại thời gian bắt đầu
    start_time = datetime.datetime.now()
    print('-' * 210)
    logger.info(f"[+] Getting network flow of {interface} in {duration} seconds.")

    # Lấy dữ liệu mạng
    error, df_metric = argus_client.get_metric(
        path_to_ra="/usr/local/bin/ra",
        server="argus-server",
        port=561,
        duration_in_seconds=duration,
    )

    # Ghi lại thời gian kết thúc
    end_time = datetime.datetime.now()
    capture_duration = (end_time - start_time).total_seconds()

    if error:
        logger.error(error)
    else:
        # Tính toán thống kê
        total_flows = len(df_metric)
        total_bytes = 0
        if 'TotBytes' in df_metric.columns:
            total_bytes = df_metric['TotBytes'].fillna(0).sum()
        lost = 0
        if 'Loss' in df_metric.columns:
            lost = df_metric['Loss'].fillna(0).sum()
            lost = str(lost)

        # Hiển thị thống kê
        logger.info("[+] Packet Capture Statistics [+] ")
        logger.info(f"<> Total network flows captured: {total_flows}")
        logger.info(f"<> Total bytes captured: {total_bytes}")
        logger.info(f"<> Lost: {lost}")
        logger.info(f"<> Duration: {capture_duration:.2f}")

        capture_duration = seconds_to_hms(capture_duration)
        packet_summary_list = [total_flows, total_bytes, lost, capture_duration]

        success, message = database.save_packetsummary(packet_summary_list)
        if success:
            logger.info(message)
        else:
            logger.error(message)

        # --- Lưu dữ liệu ban đầu vào CSV ---
        """
        timestamp = datetime.datetime.now().strftime("%d%m%Y-%H:%M:%S")
        csv_filename = f"argus_capture_{timestamp}.csv"
        logger.info(f" [+] Network Traffic saved to {csv_filename}.")
        print('-' * 210)
        print(" [+] Initial Traffic: ")
        print(df_metric)
        print('-' * 210)
        """

        # Lưu dữ liệu ban đầu vào cơ sở dữ liệu
        success, message = database.save_df_to_database(df_metric, "raw_network_traffic")
        if success:
            logger.info(message)
        else:
            logger.error(message)

        # One-hot encoding
        df = pd.get_dummies(df_metric, columns=['Proto', 'State', 'Flgs'], prefix='', prefix_sep='', dtype=int)

        # Chỉ giữ các one-hot column cần thiết
        required_onehot = ['tcp', 'icmp', 'RST', 'REQ', 'CON', 'FIN', 'INT', ' e        ', ' e d      ']
        for col in required_onehot:
            if col not in df.columns:
                df[col] = 0

        # Tạo trường nhị phân 'Status'
        df['Status'] = df_metric['Cause'].apply(lambda x: 1 if x == 'Status' else 0)

        # Danh sách cột đầu vào cho mô hình theo thứ tự
        required_columns = [
            'tcp', 'AckDat', 'sHops', 'Seq', 'RST', 'TcpRtt', 'REQ', 'dMeanPktSz',
            'Offset', 'CON', 'FIN', 'sTtl', ' e        ', 'INT', 'Mean', 'Status',
            'icmp', 'SrcTCPBase', ' e d      ', 'sMeanPktSz', 'DstLoss', 'Loss',
            'dTtl', 'SrcBytes', 'TotBytes'
        ]

        for col in required_columns:
            if col not in df.columns:
                df[col] = 0

        df_final = df[required_columns]
        df_final = df_final.fillna(0)

        # --- Lưu dữ liệu đã xử lý vào CSV ---
        """
        df_final.to_csv(csv_filename, index=False)
        print("[+] Proccessed Traffic: ")
        print(df_final)
        print("-" * 210)
        """

        # Lưu vào cơ sở dữ liệu
        success, message = database.save_df_to_database(df_final, "processed_network_traffic")
        if success:
            logger.info(message)
        else:
            logger.error(message)

        # Dự đoán với mô hình
        y_preds = rf_model.predict(df_final)

        # Chuẩn bị danh sách kết quả dự đoán để lưu
        predictions_list = []

        # --- Lưu kết quả dự đoán vào CSV ---
        """
        with open('prediction_results.txt', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Sample Index', 'Time', 'Label', 'Attack Type', 'Attack Tool'])
            print("\nPresenting Results:")
        """
        for idx, y_pred in enumerate(y_preds):
            try:
                label, attack_type, tool = y_pred.split('_')
            except:
                label, attack_type, tool = y_pred, 'Unknown', 'Unknown'
            current_time = datetime.datetime.now(pytz.timezone('Etc/GMT-7')).strftime("%H:%M:%S-%d/%m/%Y")
            predictions_list.append((idx + 1, current_time, label, attack_type, tool))

        success, message = database.save_predictions(predictions_list)
        if success:
            logger.info(message)
        else:
            logger.error(message)

    # --- Dừng Argus server ---
    """
    if started:
        argus.kill_argus(process)
    else:
        argus.kill_argus()

    while True:
        logger.info("Stopping the argus server ...")
        time.sleep(3)
        is_running, pid = argus.is_argus_server_running()
        if not is_running:
            logger.info("The argus server is stopped.")
            break
    """
