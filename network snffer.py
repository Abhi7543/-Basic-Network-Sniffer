from scapy.all import IP,TCP,UDP
def packet_callback(packet):
  if packet.haslayer(IP):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    print(f"IP Packet: {src_ip} --> {dst_ip} Protocol: {protocol}")
  if packet.haslayer(TCP):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    print(f"TCP Packet: {src_port} --> {dst_port}")
  if packet.haslayer(UDP):
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    print(f"UDP Packet: {src_port} --> {dst_port}")
