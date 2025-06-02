#!/usr/bin/env python3
"""
Simple UDP client to test the LoRaWAN server
"""

import socket
import struct
import json
import base64
import time

def send_semtech_packet():
    """Send a test Semtech UDP packet"""
    
    # Create a test PUSH_DATA packet
    # Format: Version(1) + Token(2) + Type(1) + GatewayEUI(8) + JSON
    version = 2
    token = 0x1234
    packet_type = 0x00  # PUSH_DATA
    gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    # Example LoRaWAN Join Request (base64 encoded)
    # This is a dummy Join Request for testing
    join_request_hex = "00FEDCBA9876543210EFCDAB8967452301ABCD12345678"
    join_request_bytes = bytes.fromhex(join_request_hex)
    join_request_b64 = base64.b64encode(join_request_bytes).decode()
    
    # JSON payload with rxpk (received packet)
    json_payload = {
        "rxpk": [{
            "time": "2025-06-02T20:06:30.123456Z",
            "tmst": 12345678,
            "freq": 868.1,
            "chan": 0,
            "rfch": 0,
            "stat": 1,
            "modu": "LORA",
            "datr": "SF7BW125",
            "codr": "4/5",
            "rssi": -35,
            "lsnr": 5.1,
            "size": len(join_request_bytes),
            "data": join_request_b64
        }]
    }
    
    json_data = json.dumps(json_payload).encode('utf-8')
    
    # Build packet
    packet = struct.pack('<BHB', version, token, packet_type) + gateway_eui + json_data
    
    # Send packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    try:
        print("Sending test packet to LoRaWAN server...")
        sock.sendto(packet, ('localhost', 1700))
        
        # Wait for ACK
        response, addr = sock.recvfrom(1024)
        print(f"Received ACK: {response.hex()}")
        
    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

def send_pull_data():
    """Send PULL_DATA packet"""
    version = 2
    token = 0x5678
    packet_type = 0x02  # PULL_DATA
    gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    packet = struct.pack('<BHB', version, token, packet_type) + gateway_eui
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    try:
        print("Sending PULL_DATA packet...")
        sock.sendto(packet, ('localhost', 1700))
        
        response, addr = sock.recvfrom(1024)
        print(f"Received PULL_ACK: {response.hex()}")
        
    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    print("LoRaWAN Server Test Client")
    print("=" * 30)
    
    # Test 1: Send PUSH_DATA with Join Request
    send_semtech_packet()
    print()
    
    # Wait a bit
    time.sleep(1)
    
    # Test 2: Send PULL_DATA
    send_pull_data()
    
    print("\nCheck your server console for activity!")