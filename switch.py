#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import os
import struct
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Structura de date pentru Tabela MAC
MAC_Table = {}
port_states = {}
root_bridge_ID = None
own_bridge_ID = None
trunk_ports = None
root_path_cost = 0
root_port = None

BPDU_MAC = '01:80:C2:00:00:00'
SWITCH_MAC = None


sender_path_cost = 0

def create_data(dst_mac, src_mac, dsap, ssap, control, bpdu_header, bpdu_config):
    # Convert MAC in bytes
    dst_mac_bytes = bytes.fromhex(dst_mac.replace(':', ''))
    src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))

    # lungimea totala a mesajului, impreuna cu bpdu
    llc_length = 2 + 3 + len(bpdu_header) + len(bpdu_config)  # LLC_HEADER + BPDU

    # Creez LLC_HEADER
    llc_header = struct.pack('!BBB', dsap, ssap, control)

    # Combin totul
    data = dst_mac_bytes + src_mac_bytes + struct.pack('!H', llc_length) + llc_header + bpdu_header + bpdu_config

    return data

# functie de citire din fisierul de configurare
def read_switch_config(switch_id):
    config_file = f"configs/switch{switch_id}.cfg"
    if not os.path.exists(config_file):
        print(f"Config file {config_file} does not exist")
        return None

    # toate datele trecute in config
    # porturile si tipul de transmisie T-trunk si 1/2 vlan
    config = {
        "priority": None,
        "interfaces": {}
    }
    
    with open(config_file, 'r') as file:
        lines = file.readlines()
        config["priority"] = int(lines[0].strip())

        for line in lines[1:]:
            parts = line.strip().split()
            interface_name = parts[0]
            vlan_or_trunk = parts[1] if len(parts) > 1 else None
            config["interfaces"][interface_name] = vlan_or_trunk

    return config

# functie pentru a determina daca a fost trimis mesaj de broadcast
def is_unicast(address):
    return not address.lower() == 'ff:ff:ff:ff:ff:ff'

def send_frame(target_interface, src_mode, target_mode, data, length, vlan_id):
    # Daca interfata sursa este trunk
    if src_mode == 'T':
        if target_mode == 'T':
            # Ambii sunt trunk: Trimit fara modificari
            send_to_link(target_interface, data, length)
        else:
            if vlan_id == int(target_mode):
                # Sursa trunk, destinatie access: Elimina tag-ul VLAN
                send_to_link(target_interface, data[0:12] + data[16:], length - 4)
    else:
        # Interfata sursa este access
        vlan_id = int(src_mode)
        if target_mode == 'T':
            # Sursa access, destinatie trunk: Adauga tag-ul VLAN
            tagged_frame = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
            send_to_link(target_interface, tagged_frame, length + 4)
        else:
            # Ambii sunt access: Verifica daca VLAN ID este acelasi
            if src_mode == target_mode:
                send_to_link(target_interface, data, length)

# functie de prelucrare a pachetelor de mesaj
def process_frame(interface, dest_mac, src_mac, data, length, switch_config, vlan_id):
    MAC_Table[src_mac] = (interface, switch_config["interfaces"].get(get_interface_name(interface)))
    src_interface_mode = switch_config["interfaces"].get(get_interface_name(interface), 'T')

    if is_unicast(dest_mac) and dest_mac in MAC_Table:
        target_interface, target_vlan = MAC_Table[dest_mac]
        if target_interface != interface:
            # Verific daca portul destinatiei nu este în starea BLOCKING
            if port_states.get(target_interface) != "BLOCKING":
                send_frame(target_interface, src_interface_mode, target_vlan, data, length, vlan_id)
    else:
        for i in interfaces:
            if i != interface:
                target_mode = switch_config["interfaces"].get(get_interface_name(i), 'T')
                # Verific daca VLAN-urile sunt compatibile inainte de a trimite
                if src_interface_mode != 'T' and target_mode != 'T':
                    if src_interface_mode == target_mode:
                        # Verific daca portul nu este in starea BLOCKING
                        if port_states.get(i) != "BLOCKING":
                            send_to_link(i, data, length)
                elif src_interface_mode == 'T' or target_mode == 'T':
                    # Verific daca portul nu este in starea BLOCKING
                    if port_states.get(i) != "BLOCKING":
                        send_frame(i, src_interface_mode, target_mode, data, length, vlan_id)




def parse_ethernet_header(data):
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# functie ce ia doar porturile trunk doar
def get_trunk_ports(switch_config):
    trunk_ports = []
    for interface, mode in switch_config["interfaces"].items():
        if mode == 'T':
            trunk_ports.append(interface)
    return trunk_ports

def initialize(switch_config):
    global root_bridge_ID, own_bridge_ID, port_states, root_path_cost, root_port
    # Initializez porturile trunk la BLOCKING
    for port in trunk_ports:
        port_states[port] = "BLOCKING"

    # Setez bridge ID-uri
    own_bridge_ID = switch_config['priority']
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    root_port = None

    # Daca switch-ul este root, seteaza toate porturile ca DESIGNATED_PORT
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_states[port] = "DESIGNATED_PORT"

def create_bpdu(root_bridge_ID, sender_bridge_ID, root_path_cost):
    # Construiesc bpdu-ul
    bpdu_format = '!QQQ'  # Formatul pentru 3 valori de 64 biti
    bpdu_content = struct.pack(bpdu_format, root_bridge_ID, sender_bridge_ID, root_path_cost)

    # Folosesc create_data pentru a forma intreg pachetul necesar
    return create_data(BPDU_MAC, SWITCH_MAC, 0x42, 0x42, 0x03, bpdu_content, b'')

def send_bdpu_every_sec():
    global root_bridge_ID, own_bridge_ID, trunk_ports, port_states, sender_path_cost

    while True:
        if own_bridge_ID == root_bridge_ID:
            for port in trunk_ports:
                if port_states[port] != "BLOCKING":
                    # Constructiesc si trimit BPDU
                    data2 = create_bpdu(root_bridge_ID, own_bridge_ID, sender_path_cost)  # sender_path_cost = 0
                    send_to_link(port, data2, 46)
        time.sleep(1)
        
def process_bpdu(interface, data):
    global root_bridge_ID, root_path_cost, root_port, own_bridge_ID, port_states, trunk_ports, sender_path_cost

    # Verific daca mac-ul este destinatie
    dst_mac_bytes = data[:6]
    # is_bpdu_frame = dst_mac_bytes == bytes.fromhex(BPDU_MAC.replace(':', ''))

    # if not is_bpdu_frame:
    #    return  # If the frame is not a BPDU frame, do not process further

    # Extrag LLC header
    dsap, ssap, control = struct.unpack('!BBB', data[12:15])
    if dsap != 0x42 or ssap != 0x42 or control != 0x03:
        return  # If it's not STP protocol, do not process further

    bpdu_offset = 17  # 6 (DST_MAC) + 6 (SRC_MAC) + 2 (LLC_LENGTH) + 3 (LLC_HEADER)

    # Unpack BPDU_HEADER si BPDU_CONFIG
    bpdu_header_format = '!B'
    bpdu_config_format = '8sL8sHHHHH'
    bpdu_header = struct.unpack_from(bpdu_header_format, data, bpdu_offset)
    bpdu_config = struct.unpack_from(bpdu_config_format, data, bpdu_offset + 1)

    flags = bpdu_header[0]
    root_bridge_id, root_path_cost, bridge_id, port_id, message_age, max_age, hello_time, forward_delay = bpdu_config

    
    received_root_bridge_ID = int.from_bytes(root_bridge_id, byteorder='big')
    received_sender_bridge_ID = int.from_bytes(bridge_id, byteorder='big')


    if received_root_bridge_ID < root_bridge_ID or (received_root_bridge_ID == root_bridge_ID and received_sender_bridge_ID < own_bridge_ID):
        # Am primit un BPDU mai bun si dau update
        root_bridge_ID = received_root_bridge_ID
        root_path_cost = root_path_cost
        root_port = interface

        # Verific daca switch-ul curent era root bridge
        if own_bridge_ID == original_root_bridge_ID:
            for port in trunk_ports:
                if port != root_port:
                    port_states[port] = "BLOCKING"

        if port_states.get(root_port) == "BLOCKING":
            port_states[root_port] = "LISTENING"

        # update_and_forward_bpdu()

    elif received_root_bridge_ID == root_bridge_ID:
        if interface == root_port and received_sender_path_cost + 10 < root_path_cost:
            root_path_cost = received_sender_path_cost + 10
        elif interface != root_port:
            if received_sender_path_cost > root_path_cost:
                if port_states.get(interface) != "DESIGNATED_PORT":
                    port_states[interface] = "DESIGNATED_PORT"
                    port_states[interface] = "LISTENING"

    elif received_sender_bridge_ID == own_bridge_ID:
        port_states[interface] = "BLOCKING"

    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_states[port] = "DESIGNATED_PORT"


def update_and_forward_bpdu():
    global root_bridge_ID, own_bridge_ID, root_path_cost, trunk_ports, port_states

    for port in trunk_ports:
        if port_states[port] != "BLOCKING":
            data = create_bpdu(root_bridge_ID, own_bridge_ID, root_path_cost)
            send_to_link(port, data, 46)  # înlocuiește cu codul real de trimitere !!!

# verifica daca este de tip
def is_bpdu(dest_mac):
    BPDU_MAC2 = '01:80:C2:00:00:00'
    return dest_mac == bytes.fromhex(BPDU_MAC2.replace(':',''))

def main():
    global trunk_ports, SWITCH_MAC, interfaces
    switch_id = sys.argv[1]
    switch_config = read_switch_config(switch_id)
    if switch_config is None:
        sys.exit(1)

    trunk_ports = get_trunk_ports(switch_config)
    initialize(switch_config)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    SWITCH_MAC = ':'.join(['%02x' % b for b in get_switch_mac()])

    if own_bridge_ID == root_bridge_ID:
        t = threading.Thread(target=send_bdpu_every_sec)
        t.start()

    while True:
        interface, data, length = recv_from_any_link()
        if is_bpdu(data[0:6]):
            process_bpdu(interface, data)
        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
            process_frame(interface, dest_mac, src_mac, data, length, switch_config, vlan_id)

if __name__ == "__main__":
    main()