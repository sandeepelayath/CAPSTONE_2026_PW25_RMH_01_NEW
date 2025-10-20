import socket
import threading
import json
import os
import time

HONEYPOT_IP = "10.0.0.9"
HONEYPOT_PORT = 22
LOG_DIR = "/tmp/honeypot_logs/"
os.makedirs(LOG_DIR, exist_ok=True)

def log_event(addr, port, data):
    event = {
        "timestamp": time.time(),
        "src_ip": addr,
        "dst_port": port,
        "bytes": len(data),
        "payload_preview": data[:100].decode(errors="replace") if isinstance(data, bytes) else str(data)
    }
    fname = f"{LOG_DIR}/event_{int(event['timestamp']*1000)}_{addr.replace('.', '_')}.json"
    with open(fname, "w") as f:
        json.dump(event, f)
        f.flush()
        os.fsync(f.fileno())

def handle_connection(conn, addr):
    print(f"Connection from {addr}")
    try:
        conn.sendall(b"Welcome to the honeypot!\n")
        data = conn.recv(4096)
    except Exception:
        data = b""
    log_event(addr[0], addr[1], data)
    conn.close()

def run_honeypot():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HONEYPOT_IP, HONEYPOT_PORT))
    s.listen(5)
    print(f"Honeypot listening on {HONEYPOT_IP}:{HONEYPOT_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run_honeypot()
