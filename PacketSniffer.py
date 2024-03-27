import scapy.all as scapy


def packet_sniffer(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {source_ip} --> Destination IP: {destination_ip} Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            payload = packet[scapy.TCP].payload
            print("TCP Packet:")
            print(payload)
        elif packet.haslayer(scapy.UDP):
            payload = packet[scapy.UDP].payload
            print("UDP Packet:")
            print(payload)


# Sniff packets on the network
scapy.sniff(filter="", prn=packet_sniffer, store=False)
