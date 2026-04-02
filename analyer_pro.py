from scapy.all import sniff, IP

def debug_packet(packet):
    if packet.haslayer(IP):
        print(f"抓到了！源IP: {packet[IP].src} -> 目的IP: {packet[IP].dst}")

print("正在探测网络流量... 请打开浏览器随便访问一个网页")

# 1. 去掉 filter，观察是否有任何 IP 包进来
# 2. 如果还是没反应，尝试添加 iface 参数，例如 iface="WLAN"
sniff(prn=debug_packet, store=0, count=20)