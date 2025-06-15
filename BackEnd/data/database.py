from xmlrpc.client import Boolean
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, insert, select, Float, Boolean
import hashlib
import logging

# Thiết lập logging
logger = logging.getLogger('Database')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)

DATABASE_NAME: str = "sqlite:////stored/5g_monitor.db"
# Tạo kết nối đến cơ sở dữ liệu SQLite
engine = create_engine(DATABASE_NAME)
metadata = MetaData()

# Định nghĩa bảng users
users = Table('users', metadata,
    Column('id', Integer, primary_key=True),
    Column('username', String, unique=True),
    Column('password', String),
)

# Định nghĩa bảng raw_network_traffic
raw_network_traffic = Table('raw_network_traffic', metadata,
    Column('id', Integer, primary_key=True),
    Column('Proto', String),
    Column('AckDat', Float),
    Column('sHops', Integer),
    Column('Seq', Float),
    Column('State', String),
    Column('TcpRtt', Float),
    Column('dmeansz', Float),
    Column('offset', Integer),
    Column('sttl', Float),
    Column('flgs', String),
    Column('mean', Float),
    Column('cause', String),
    Column('stcpb', String),
    Column('dloss', String),
    Column('smeansz', String),
    Column('loss', Float),
    Column('dttl', Float),
    Column('sbytes', Integer),
    Column('bytes', Integer),
)

# Định nghĩa bảng processed_network_traffic
processed_network_traffic = Table('processed_network_traffic', metadata,
    Column('id', Integer, primary_key=True),
    Column('tcp', Boolean),
    Column('AckDat', Float),
    Column('sHops', Integer),
    Column('Seq', Float),
    Column('RST', Boolean),
    Column('TcpRtt', Float),
    Column('REQ', Boolean),
    Column('dMeanPktSz', Float),
    Column('Offset', Integer),
    Column('CON', Boolean),
    Column('FIN', Boolean),
    Column('sTtl', Float),
    Column('e', Boolean),
    Column('INT', Boolean),
    Column('Mean', Float),
    Column('Status', Boolean),
    Column('icmp', Boolean),
    Column('SrcTCPBase', Float),
    Column('e d', String),
    Column('sMeanPktSz', String),
    Column('DstLoss', String),
    Column('Loss', Float),
    Column('dTtl', Float),
    Column('SrcBytes', Integer),
    Column('TotBytes', Integer),
)

# Định nghĩa bảng prediction_results
prediction_results = Table('prediction_results', metadata,
    Column('id', Integer, primary_key=True),
    Column('sample_index', Integer),
    Column('time', String),
    Column('label', String),
    Column('attack_type', String),
    Column('attack_tool', String),
)

# Định nghĩa bảng packet_summary
packet_summary = Table('packet_summary', metadata,
    Column('id', Integer, primary_key=True),
    Column('total_flows', Integer),
    Column('total_bytes', Float),
    Column('lost', String),
    Column('capture_duration', String),
)

# Tạo bảng nếu chưa tồn tại
metadata.create_all(engine)

# Thêm người dùng mẫu khi chưa có người dùng nào trong DB
def init_users():
    conn = engine.connect()
    result = conn.execute(select(users))
    user_exists = result.fetchone()
    if not user_exists:
        # Mã hóa mật khẩu bằng sha256
        conn.execute(insert(users).values(
            username='viethoang',
            password=hashlib.sha256('22520471'.encode()).hexdigest()
        ))
        conn.execute(insert(users).values(
            username='bacan',
            password=hashlib.sha256('22520143'.encode()).hexdigest()
        ))
        conn.commit()
    conn.close()

# Khởi tạo người dùng mẫu
init_users()

# Lưu DataFrame vào cơ sở dữ liệu
def save_df_to_database(df, table_name, if_exists='replace'):
    try:
        # Lưu vào cơ sở dữ liệu
        df.to_sql(name=table_name, con=engine, if_exists=if_exists, index=False)
        logger.info(f"Đã lưu {len(df)} bản ghi vào bảng {table_name}")
        return True, f"Đã lưu {len(df)} bản ghi vào bảng {table_name}"
    except Exception as e:
        logger.error(f"Lỗi khi lưu vào bảng {table_name}: {str(e)}")
        return False, f"Lỗi khi lưu vào bảng {table_name}: {str(e)}"

# Lưu kết quả dự đoán vào cơ sở dữ liệu
def save_predictions(predictions_list):
    try:
        conn = engine.connect()
        trans = conn.begin()
        conn.execute(prediction_results.delete())

        for pred in predictions_list:
            idx, time_str, label, attack_type, tool = pred
            conn.execute(insert(prediction_results).values(
                sample_index=idx,
                time=time_str,
                label=label,
                attack_type=attack_type,
                attack_tool=tool,
            ))

        trans.commit()
        conn.commit()
        conn.close()
        return True, f"Đã lưu {len(predictions_list)} kết quả dự đoán"
    except Exception as e:
        logger.error(f"Lỗi khi lưu kết quả dự đoán: {str(e)}")
        return False, f"Lỗi khi lưu kết quả dự đoán: {str(e)}"

def save_packetsummary(summary_data):
    try:
        conn = engine.connect()
        trans = conn.begin()
        conn.execute(packet_summary.delete())

        conn.execute(insert(packet_summary).values(
            total_flows=summary_data[0],
            total_bytes=summary_data[1],
            lost=summary_data[2],
            capture_duration=summary_data[3],
        ))
        trans.commit()
        conn.close()
        return True, "Đã lưu thông tin Packet Summary"
    except Exception as e:
        logger.error(f"Lỗi khi lưu Packet Summary: {str(e)}")
        return False, f"Lỗi khi lưu Packet Summary: {str(e)}"