from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import os
import hashlib
import logging
import numpy as np
from data import database
from data.fetch_data import load_raw_network_traffic, load_processed_network_traffic, load_sample_prediction, get_packet_summary
from capture.flow_capture import run_capture
from sqlalchemy import select, bindparam

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key='your_secret_key')

FRONTEND_DIR = "../FrontEnd/"


@app.post("/api/login")
async def login(request: Request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return JSONResponse({'success': False, 'message': 'Vui lòng nhập tên đăng nhập và mật khẩu!'}, status_code=400)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    with database.engine.connect() as conn:
        result = conn.execute(
            select(database.users).where(
                (database.users.c.username == username) &
                (database.users.c.password == hashed_password)
            )
        )
        user = result.fetchone()
    if user:
        request.session['username'] = username
        return {"success": True}
    else:
        return JSONResponse({'success': False, 'message': 'Tên đăng nhập hoặc mật khẩu không chính xác!'}, status_code=401)

@app.get("/api/user")
async def get_user(request: Request):
    username = request.session.get('username')
    if username:
        return {"username": username}
    return JSONResponse({'username': None}, status_code=401)

@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return Response(status_code=204)

@app.get("/")
async def root():
    file_path = os.path.join(FRONTEND_DIR, 'login-page.html')
    
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='text/html')
    return JSONResponse({"error": "Index file not found"}, status_code=404)



@app.post("/api/capture")
async def api_run_capture(request: Request):
    data = await request.json()
    interface = str(data.get('interface', 'any')).strip()
    time_val = data.get('time', 30)
    try:
        duration = int(time_val)
        if not interface:
            return JSONResponse({'success': False, 'message': 'Vui lòng chọn giao diện mạng!'}, status_code=400)
        if duration <= 0:
            return JSONResponse({'success': False, 'message': 'Thời gian giám sát phải là số nguyên dương!'}, status_code=400)
    except (ValueError, TypeError):
        return JSONResponse({'success': False, 'message': 'Thời gian giám sát phải là số nguyên dương!'}, status_code=400)
    try:
        run_capture(interface, duration)
        return {"success": True, "message": "Capture & phân tích thành công"}
    except Exception as e:
        logging.exception("Lỗi khi chạy run_capture")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.get("/api/raw_network_traffic")
async def api_raw_network_traffic():
    df = load_raw_network_traffic()
    
    if df.isnull().values.any():
        data = df.replace({np.nan: None}).to_dict(orient='records')
    else:
        data = df.to_dict(orient='records')
    return JSONResponse(content=data)


@app.get("/api/processed_network_traffic")
async def api_processed_network_traffic():
    data = load_processed_network_traffic().to_dict(orient='records')
    return JSONResponse(content=data)

@app.get("/api/sample_prediction")
async def api_sample_prediction():
    data = load_sample_prediction().to_dict(orient='records')
    return JSONResponse(content=data)
    

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

@app.get("/api/packet_summary")
async def api_packet_summary():
    summary = get_packet_summary()
    summary = convert_numpy_types(summary)
    if summary is None:
        return JSONResponse(content={})
    return JSONResponse(content=summary)


@app.get("/api/detection_results/{sample_index}")
async def api_detection_results(sample_index: int):
    from data.database import engine, prediction_results
   
    with engine.connect() as conn:
        query = select(prediction_results).where(prediction_results.c.sample_index == bindparam('sample_idx'))
        results = conn.execute(query, {'sample_idx': sample_index}).fetchall()
    alerts = []
    for result in results:
        alerts.append({
            "label": result.label,
            "attack_type": result.attack_type,
            "attack_tool": result.attack_tool,
            "time": str(result.time)
        })
    return alerts

@app.get("/healthcheck")
async def healthcheck():
    return Response(status_code=200)


@app.get("/{filename:path}")
async def serve_static(filename: str):
    
    filename = filename.rstrip("/")
    file_path = os.path.join(FRONTEND_DIR, filename)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return JSONResponse({"error": "File not found"}, status_code=404)


if __name__ == "__main__":
    import os
    keyfile = "server.key"
    certfile = "server.crt"
    evm_path = "server.conf"
    if os.path.exists(evm_path):
        with open(evm_path) as f:
            for line in f:
                if line.startswith("SSL_KEYFILE="):
                    keyfile = line.strip().split("=", 1)[1]
                elif line.startswith("SSL_CERTFILE="):
                    certfile = line.strip().split("=", 1)[1]
                elif line.startswith('FRONTEND_DIR='):
                    FRONTEND_DIR = line.strip().split('=', 1)[1]
                    if not os.path.isabs(FRONTEND_DIR):
                        FRONTEND_DIR = os.path.join(os.path.dirname(__file__), FRONTEND_DIR)
    
    print(f"Serving frontend from: {FRONTEND_DIR}")

    try:
        import hypercorn.asyncio
        import asyncio
        from hypercorn.config import Config
        
        config = Config()
        config.bind = ["0.0.0.0:8110"]
        config.certfile = certfile
        config.keyfile = keyfile
        config.use_reloader = True
        config.alpn_protocols = ["h2"]
        asyncio.run(hypercorn.asyncio.serve(app, config))
    except ImportError:
        print(u"Bạn cần cài đặt hypercorn để chạy HTTP/2. Hãy chạy: pip install hypercorn")
        print(u"Hoặc tiếp tục dùng uvicorn (chỉ hỗ trợ HTTP/1.1)")
        import uvicorn
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8110,
            ssl_keyfile=keyfile,
            ssl_certfile=certfile,
            reload=True
        )
