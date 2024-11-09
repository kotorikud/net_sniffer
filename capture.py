from time import sleep
from winpcapy import WinPcapUtils
import dictionary

def capture_packet(win_pcap, param, header, pkt_data):
    # Extract and format MAC addresses
    dest_mac = ":".join(f"{byte:02x}" for byte in pkt_data[6:12])
    source_mac = ":".join(f"{byte:02x}" for byte in pkt_data[0:6])

    # Extract IP frame from packet and IP addresses
    ip_packet = pkt_data[14:]
    src_ip_address = ".".join(str(byte) for byte in ip_packet[12:16])
    dst_ip_address = ".".join(str(byte) for byte in ip_packet[16:20])

    # Convert packet data to hex representation
    hex_data = ['%02X' % byte for byte in pkt_data]
    dictionary.scratch_data.append(hex_data)
    dictionary.scracth_countor += 1


    packet_key = (
        f"{dictionary.scracth_countor}: 源MAC: {source_mac} 目的MAC: {dest_mac} "
        f"源IP: {src_ip_address} 目的IP: {dst_ip_address}"
    )
    # Store packet data in dictionary
    dictionary.dict[packet_key] = hex_data

    sleep(0.05)

def start():
    WinPcapUtils.capture_on(dictionary.checked_packet, capture_packet)
