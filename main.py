import socket
import json
import time
from base64 import b64decode, b64encode
from devices import registered_devices
from lorawan.phypayload import PHYpayload
from lorawan.loramac import lorawan_join_accept, derive_keys

UDP_IP = "0.0.0.0"
UDP_PORT = 1700

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))
print(f"[LoRaWAN Server] Listening on UDP {UDP_PORT}")

def handle_packet(data, addr):
    try:
        pkt_json = json.loads(data.decode())
        if 'rxpk' not in pkt_json:
            return

        for pkt in pkt_json['rxpk']:
            phy_payload_b64 = pkt.get("data")
            phy_payload = b64decode(phy_payload_b64)
            phy = PHYpayload(phy_payload)

            if phy.mhdr.mtype != "JoinRequest":
                print("[!] Not a JoinRequest")
                return

            dev_eui = phy.payload.dev_eui.hex().upper()
            join_eui = phy.payload.app_eui.hex().upper()
            dev_nonce = phy.payload.dev_nonce.hex().upper()

            print(f"[+] JoinRequest received from DevEUI: {dev_eui}")

            if dev_eui not in registered_devices:
                print("[!] Unknown device")
                return

            device = registered_devices[dev_eui]
            app_key = device['app_key']

            if dev_nonce in device['used_nonces']:
                print("[!] DevNonce replay detected")
                return

            if not phy.validate_mic(app_key):
                print("[!] Invalid MIC")
                return

            device['used_nonces'].add(dev_nonce)

            app_nonce = b'\x01\x02\x03'
            net_id = b'\x00\x00\x01'
            dev_addr = b'\x26\x01\x1B\x77'

            nwk_skey, app_skey = derive_keys(app_key, app_nonce, net_id, phy.payload.dev_nonce)

            join_accept = lorawan_join_accept(app_key, app_nonce, net_id, dev_addr, dl_settings=b'\x00', rx_delay=b'\x01', cflist=None)
            send_join_accept(sock, addr, join_accept)
            print("[*] JoinAccept sent")

    except Exception as e:
        print(f"[Error] {e}")

def send_join_accept(sock, gateway_addr, join_accept_payload):
    response = {
        "txpk": {
            "imme": True,
            "freq": 868.1,
            "rfch": 0,
            "powe": 14,
            "modu": "LORA",
            "datr": "SF7BW125",
            "codr": "4/5",
            "ipol": True,
            "size": len(join_accept_payload),
            "data": b64encode(join_accept_payload).decode()
        }
    }
    sock.sendto(json.dumps(response).encode(), gateway_addr)

while True:
    data, addr = sock.recvfrom(4096)
    handle_packet(data, addr)
