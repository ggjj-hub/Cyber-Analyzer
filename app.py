import threading
import time
import csv
import requests
import logging
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
from collections import Counter

# 屏蔽无关警告，让控制台清爽
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# 全局存储
stats = Counter()
location_cache = {}
display_buffer = []  # 基础流量缓冲区
dpi_buffer = []  # 域名解析缓冲区
lock = threading.Lock()


def get_location(ip):
    """获取 IP 地理位置，带缓存机制"""
    if ip in location_cache: return location_cache[ip]
    if ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("10."):
        return "局域网"
    try:
        # 使用 ip-api 免费接口
        res = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=1).json()
        loc = f"{res.get('city', '未知')} ({res.get('country', '外网')})" if res.get(
            'status') == 'success' else "查询中..."
        location_cache[ip] = loc
        return loc
    except:
        return "未知位置"


def get_domain(packet):
    """深度解析域名 (HTTP/HTTPS)"""
    try:
        if packet.haslayer(HTTPRequest):
            host = packet[HTTPRequest].Host
            return host.decode(errors='ignore') if host else None
        if packet.haslayer(TLSClientHello):
            sni = packet[TLSClientHello].getlayer(TLS_Ext_ServerName)
            if sni: return sni.servernames[0].servername.decode(errors='ignore')
    except:
        pass
    return None


def packet_monitoring():
    """高性能抓包主线程"""

    def process_packet(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"

            with lock:
                stats[proto] += 1
                domain = get_domain(packet)
                loc = get_location(src_ip)

                # 记录基础流量
                entry = {
                    'src': src_ip, 'dst': dst_ip,
                    'proto': proto, 'loc': loc,
                    'domain': domain if domain else ""
                }
                display_buffer.append(entry)
                if len(display_buffer) > 20: display_buffer.pop(0)

    sniff(prn=process_packet, store=0)


def emit_data():
    """定时推送到前端，每 0.5 秒一次，防止前端渲染崩溃"""
    while True:
        with lock:
            if display_buffer:
                socketio.emit('update', {
                    'stats': dict(stats),
                    'logs': display_buffer[-10:]  # 只推最新的 10 条
                })
        time.sleep(0.5)


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    # 打印启动提示
    print("=" * 50)
    print("SYSTEM NETWORK ANALYZER v3.0 启动成功")
    print("浏览器访问: http://127.0.0.1:5000")
    print("=" * 50)

    threading.Thread(target=packet_monitoring, daemon=True).start()
    threading.Thread(target=emit_data, daemon=True).start()
    socketio.run(app, port=5000, debug=False, allow_unsafe_werkzeug=True)