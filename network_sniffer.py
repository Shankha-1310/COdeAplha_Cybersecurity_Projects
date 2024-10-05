import scapy.all as scapy

def sniff_packets(interface, count):
    """
    Sniff packets on the specified interface for the specified count.

    Args:
        interface (str): The interface to sniff on (e.g. "eth0", "wlan0", etc.)
        count (int): The number of packets to capture

    Returns:
        A list of captured packets
    """
    scapy.conf.verb = 0  # disable verbose mode
    packets = scapy.sniff(iface=interface, count=count)
    return packets

def print_packet_info(packet):
    """
    Print information about a captured packet.

    Args:
        packet (scapy.packet.Packet): The captured packet
    """
    print("Packet Info:")
    if packet.haslayer(scapy.IP):
        print(f"  Source IP: {packet[scapy.IP].src}")
        print(f"  Destination IP: {packet[scapy.IP].dst}")
    else:
        print("  No IP layer found in the packet")
    if packet.haslayer(scapy.Ether):
        print(f"  Protocol: {packet[scapy.Ether].type}")
        print(f"  Destination MAC: {packet[scapy.Ether].dst}")
    if packet.haslayer(scapy.TCP):
        print(f"  Source Port: {packet[scapy.TCP].sport}")
        print(f"  Destination Port: {packet[scapy.TCP].dport}")
    print(f"  Protocol: {packet[scapy.Ether].type}")
    print(f"  Length: {len(packet)} bytes")

def print_http_info(packet):
    """
    Print information about an HTTP packet.

    Args:
        packet (scapy.packet.Packet): The captured packet
    """
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        if src_port == 80 or dst_port == 80:  # HTTP port
            print("HTTP Packet:")
            print(f"  Source IP: {src_ip}")
            print(f"  Destination IP: {dst_ip}")
            print(f"  Source Port: {src_port}")
            print(f"  Destination Port: {dst_port}")
            if packet.haslayer(scapy.Raw):
                http_data = packet[scapy.Raw].load
                if b"GET" in http_data or b"POST" in http_data:
                    print("  HTTP Request:")
                    print(f"    {http_data.decode('utf-8')}")

def main():
    interface = "eth0"  # change to your desired interface
    count = 10  # change to your desired packet count

    packets = sniff_packets(interface, count)

    for packet in packets:
        print_packet_info(packet)
        print_http_info(packet)
        print()  # empty line for readability

if __name__ == "__main__":
    main()

