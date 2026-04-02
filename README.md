# Cyber-Analyzer v3.0 🚀
基于 Python Scapy 和 Flask 的实时网络协议分析与可视化工具。

### 🌟 功能特点
- **协议分析**：实时解析 IP, TCP, UDP 协议占比。
- **DPI 深度解析**：识别 HTTP/HTTPS (TLS SNI) 访问域名。
- **地理定位**：集成 IP-API，自动识别外网 IP 物理城市。
- **可视化看板**：基于 ECharts 的科技感动态监控界面。
- **日志持久化**：自动记录异常流量至 CSV 文件。

### 🛠️ 环境要求
- Windows (需安装 [Npcap](https://npcap.com/#download))
- Python 3.8+

### 🚀 快速启动
1. 安装依赖：`pip install flask flask-socketio scapy requests cryptography`
2. 以管理员权限运行：`python app.py`
3. 访问浏览器：`http://127.0.0.1:5000`