from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "Unknown"

            if TCP in packet:
                protocol = "TCP"
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                protocol = "UDP"
                payload = bytes(packet[UDP].payload)
            else:
                payload = b""

            print("\n--- Packet Captured ---")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Protocol: {protocol}")
            print(f"Payload: {payload[:50]} (truncated)" if payload else "Payload: None")
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to start packet sniffing
def start_sniffing(interface):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Packet Sniffer Tool for Educational Purposes")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to sniff on")
    args = parser.parse_args()

    print("Packet Sniffer Tool (Educational Use Only)")
    print("Ensure you have appropriate permissions to use this tool.")
    start_sniffing(args.interface)
