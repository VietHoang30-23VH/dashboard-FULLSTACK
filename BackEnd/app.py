from flask import Flask, jsonify, session, request, send_from_directory
from flask_cors import CORS
import os
from sqlalchemy import select, bindparam
import hashlib
import logging
from data import database
from data.fetch_data import load_raw_network_traffic, load_processed_network_traffic, load_sample_prediction, get_packet_summary
from capture.flow_capture import run_capture
import numpy as np

app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(app, supports_credentials=True)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Vui lòng nhập tên đăng nhập và mật khẩu!'}), 400
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    conn = database.engine.connect()
    result = conn.execute(
        select(database.users).where(
            (database.users.c.username == username) &
            (database.users.c.password == hashed_password)
        )
    )
    user = result.fetchone()
    conn.close()
    if user:
        session['username'] = username
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Tên đăng nhập hoặc mật khẩu không chính xác!'}), 401

@app.route('/api/user')
def get_user():
    username = session.get('username')
    if username:
        return jsonify({'username': username})
    return jsonify({'username': None}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return '', 204

# Route phục vụ file tĩnh cho FrontEnd
@app.route('/<path:filename>')
def serve_static(filename):
    frontend_dir = os.path.join(os.path.dirname(__file__), '../FrontEnd/page')
    return send_from_directory(frontend_dir, filename)

@app.route('/')
def root():
    return 'Server is running on port 8110', 200

@app.route('/api/capture', methods=['POST'])
def api_run_capture():
    data = request.get_json() or {}
    interface = str(data.get('interface', 'any')).strip()
    time_val = data.get('time', 30)
    try:
        duration = int(time_val)
        if not interface:
            return jsonify({'success': False, 'message': 'Vui lòng chọn giao diện mạng!'}), 400
        if duration <= 0:
            return jsonify({'success': False, 'message': 'Thời gian giám sát phải là số nguyên dương!'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Thời gian giám sát phải là số nguyên dương!'}), 400

    try:
        run_capture(interface, duration)
        return jsonify({"success": True, "message": "Capture & phân tích thành công"})
    except Exception as e:
        logging.exception("Lỗi khi chạy run_capture")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/raw_network_traffic')
def api_raw_network_traffic():
    df = load_raw_network_traffic()
    data = df.replace({np.nan: None}).to_dict(orient='records')
    return jsonify(data)

@app.route('/api/processed_network_traffic')
def api_processed_network_traffic():
    df = load_processed_network_traffic()
    return jsonify(df.to_dict(orient='records'))

@app.route('/api/sample_prediction')
def api_sample_prediction():
    df = load_sample_prediction()
    return jsonify(df.to_dict(orient='records'))

def convert_numpy_types(obj):
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(i) for i in obj]
    elif isinstance(obj, (np.integer, np.int64)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64)):
        return float(obj)
    else:
        return obj

@app.route('/api/packet_summary')
def api_packet_summary():
    summary = get_packet_summary()  
    summary = convert_numpy_types(summary)
    return jsonify(summary if summary else {})

@app.route('/api/detection_results/<int:sample_index>')
def api_detection_results(sample_index):
    from data.database import engine, prediction_results  # đảm bảo import đúng
    conn = engine.connect()
    query = select(prediction_results).where(prediction_results.c.sample_index == bindparam('sample_idx'))
    results = conn.execute(query, {'sample_idx': sample_index}).fetchall()
    conn.close()
    alerts = []
    for result in results:
        alerts.append({
            "label": result.label,
            "attack_type": result.attack_type,
            "attack_tool": result.attack_tool,
            "time": str(result.time)
        })
    return jsonify(alerts)


if __name__ == '__main__':
    app.run(debug=True, port=8110)