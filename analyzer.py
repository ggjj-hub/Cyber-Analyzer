from scapy.all import sniff, IP, TCP


def packet_callback(packet):
    # 检查数据包是否包含 IP 层
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] 源IP: {src_ip} -> 目的IP: {dst_ip} | 协议代码: {proto}")


# 启动抓包
print("正在启动实时抓包... (按下 Ctrl+C 停止)")
sniff(prn=packet_callback, store=0)