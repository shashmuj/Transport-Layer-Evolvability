import argparse
import contextlib
from scapy.all import *
import os


def generate_random_bytes(length):
    return os.urandom(length)

def handle_packet(packet):
    dst_port = packet[UDP].dport
    log_path = f"{log_folder}quic_receiver_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            if packet:
                print("Initial Packet received: ")
                packet.show2()
                hexdump(packet)
            if packet.haslayer(UDP):
                ip = IP(src=packet[IP].dst, dst=packet[IP].src)
                udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
                if Raw in packet:
                    quic_initial_header = packet[Raw].load
                    
                    if len(quic_initial_header) >= 11:
                        c_cid = quic_initial_header[5:11]
                        print("client connection id: ", c_cid)

                        header_form = 1 << 7
                        fixed_bit = 1 << 6
                        long_packet_type = 0 << 4
                        reserved_bits = 0 << 2
                        packet_number_length = 0
                        first_byte = header_form | fixed_bit | long_packet_type | reserved_bits
                        
                        version = 1
                        
                        src_conn_id_length = 5
                        src_conn_id = generate_random_bytes(src_conn_id_length)
                        
                        packet_number = generate_random_bytes(packet_number_length + 1)
                        
                        response_initial_header = (
                                    bytes([first_byte]) +
                                    version.to_bytes(4, 'big') +
                                    c_cid + 
                                    bytes([src_conn_id_length]) +
                                    src_conn_id +
                                    len(b'').to_bytes(1, 'big') +
                                    bytes.fromhex('40 75') +
                                    packet_number + 
                                    generate_random_bytes(116)
                        )
                        
                        response_inital_packet = ip / udp / Raw(load=response_initial_header)
                        
                        send(response_inital_packet)
                        print("Response packet sent:")
                        response_inital_packet.show2()
                        hexdump(response_inital_packet)
        

def main(ip_filter):
    os.makedirs(log_folder, exist_ok=True)
    
    print("Listening for incoming QUIC packets...")
    sniff(filter=ip_filter, prn=handle_packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="filter IP address")
    parser.add_argument('--ip', type=str, default='128.105.144.164')
    parser.add_argument('--fd', type=str, default='campus')
    args = parser.parse_args()

    ip = args.ip
    fd = args.fd
    
    log_folder = f"logs/quic/{fd}/"
    
    ip_filter = "udp and src host " + ip
    main(ip_filter)
