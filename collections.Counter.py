import matplotlib.pyplot as plt
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest  # 必须显式导入这个！
from scapy.layers.tls.extensions import TLS_Ext_ServerName # 用于提取HTTPS域名
from scapy.layers.tls.handshake import TLSClientHello
from collections import Counter

# 解决中文显示问题
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

# 初始化数据
stats = Counter()

def get_domain(packet):
    """尝试从包中提取域名"""
    # 1. 解析 HTTP 域名
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host
        return host.decode(errors='ignore') if host else "Unknown HTTP"

    # 2. 解析 HTTPS (TLS) 域名 (SNI)
    if packet.haslayer(TLSClientHello):
        # 遍历 TLS 扩展寻找 ServerName
        try:
            sni_extension = packet[TLSClientHello].getlayer(TLS_Ext_ServerName)
            if sni_extension:
                # 提取域名列表中的第一个
                server_name = sni_extension.servernames[0].servername
                return server_name.decode(errors='ignore')
        except:
            pass
    return None

def plot_stats(data_dict):
    plt.clf()
    labels = list(data_dict.keys())
    values = list(data_dict.values())
    plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("实时网络协议分布图")
    plt.pause(0.1)

def monitor_callback(packet):
    if packet.haslayer(IP):
        # 协议统计逻辑
        if packet.haslayer(TCP):
            proto = "TCP"
            # 尝试深度解析：看看能不能抓到域名
            domain = get_domain(packet)
            if domain:
                print(f"  [发现目标] 正在访问: {domain}")
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "Other"

        stats[proto] += 1

        if sum(stats.values()) % 50 == 0:
            plot_stats(stats)

# 开启交互模式
plt.ion()
plt.figure(figsize=(8, 6))

print("开始抓包分析... (若无法解析域名，请尝试在浏览器访问 http://neverssl.com)")
sniff(prn=monitor_callback, store=0)