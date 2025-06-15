import pandas as pd
import logging
from sqlalchemy import create_engine
from data.database import prediction_results DATABASE_NAME
from sqlalchemy import select, bindparam  # Thêm import cho select và bindparam

# Thiết lập logging
logger = logging.getLogger('Database')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Kết nối tới SQLite database
engine = create_engine(DATABASE_NAME)

# Hàm load dữ liệu từ bảng raw_network_traffic
def load_raw_network_traffic():
    try:
        df = pd.read_sql_table('raw_network_traffic', con=engine)
        return df
    except Exception as e:
        logger.error(f"Lỗi khi load dữ liệu raw_network_traffic: {str(e)}")
        return pd.DataFrame()

# Hàm load dữ liệu từ bảng processed_network_traffic
def load_processed_network_traffic():
    try:
        df = pd.read_sql_table('processed_network_traffic', con=engine)
        return df
    except Exception as e:
        logger.error(f"Lỗi khi load dữ liệu processed_network_traffic: {str(e)}")
        return pd.DataFrame()  # Trả về DataFrame rỗng nếu lỗi
    
def load_sample_prediction():
    try:
        df = pd.read_sql_table('prediction_results', con=engine)
        return df
    except Exception as e:
        logger.error(f"Lỗi khi load dữ liệu prediction_results: {str(e)}")
        return pd.DataFrame()  # Trả về DataFrame rỗng nếu lỗi    

def get_packet_summary():
    try:    
        query = "SELECT total_flows, total_bytes, lost, capture_duration FROM packet_summary"
        df = pd.read_sql(query, engine)
        if df.empty:
            return None
        row = df.iloc[0]
        packetsummary = {
            'total_flows': row['total_flows'],
            'total_bytes': row['total_bytes'],
            'lost': row['lost'],
            'capture_duration': row['capture_duration'],
        }
        return packetsummary
    except Exception as e:
        logger.error(f"Lỗi khi lấy dữ liệu packet summary: {str(e)}")
        return None
    
def get_detection_results_by_sample_index(sample_index):

    conn = engine.connect()
    query = select(prediction_results).where(prediction_results.c.sample_index == bindparam('sample_idx'))
    results = conn.execute(query, {'sample_idx': sample_index}).fetchall()
    conn.close()
    return results