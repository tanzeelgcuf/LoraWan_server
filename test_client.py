#!/usr/bin/env python3
"""
Enhanced UDP client to test the LoRaWAN server with realistic gateway behavior
"""

import socket
import struct
import json
import base64
import time
import threading

def create_join_request():
    """Create a realistic LoRaWAN Join Request"""
    # Use the DevEUI from the example device in the server
    app_eui = bytes.fromhex("FEDCBA9876543210")  # Little endian in packet
    dev_eui = bytes.fromhex("EFCDAB8967452301")  # Little endian in packet  
    dev_nonce = bytes.fromhex("ABCD")
    
    # MHDR for Join Request
    mhdr = 0x00  # Join Request
    
    # Build Join Request: MHDR + AppEUI + DevEUI + DevNonce + MIC
    join_request = bytes([mhdr]) + app_eui + dev_eui + dev_nonce + bytes(4)  # 4-byte placeholder MIC
    
    return join_request

def send_join_request():
    """Send a Join Request via PUSH_DATA"""
    version = 2
    token = 0x1234
    packet_type = 0x00  # PUSH_DATA
    gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    # Create Join Request
    join_request = create_join_request()
    join_request_b64 = base64.b64encode(join_request).decode()
    
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
            "size": len(join_request),
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
        print("Sending Join Request to LoRaWAN server...")
        print(f"DevEUI: {join_request[9:17][::-1].hex().upper()}")  # Reverse for display
        print(f"AppEUI: {join_request[1:9][::-1].hex().upper()}")   # Reverse for display
        
        sock.sendto(packet, ('localhost', 1700))
        
        # Wait for ACK
        response, addr = sock.recvfrom(1024)
        print(f"Received PUSH_ACK: {response.hex()}")
        
    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

def simulate_gateway_pull():
    """Simulate gateway PULL_DATA behavior to receive downlinks"""
    version = 2
    token = 0x5678
    packet_type = 0x02  # PULL_DATA
    gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    packet = struct.pack('<BHB', version, token, packet_type) + gateway_eui
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)  # Longer timeout for potential downlink
    
    try:
        print("Sending PULL_DATA (checking for downlinks)...")
        sock.sendto(packet, ('localhost', 1700))
        
        # Wait for response
        while True:
            try:
                response, addr = sock.recvfrom(1024)
                
                if len(response) >= 4:
                    resp_version = response[0]
                    resp_token = struct.unpack('<H', response[1:3])[0]
                    resp_type = response[3]
                    
                    if resp_type == 0x04:  # PULL_ACK
                        print(f"Received PULL_ACK: {response.hex()}")
                    elif resp_type == 0x03:  # PULL_RESP (downlink)
                        print(f"Received PULL_RESP (downlink): {response.hex()}")
                        
                        # Parse JSON payload
                        if len(response) > 4:
                            try:
                                json_data = response[4:].decode('utf-8')
                                downlink = json.loads(json_data)
                                print(f"Downlink payload: {json.dumps(downlink, indent=2)}")
                                
                                # Extract and decode Join Accept
                                if 'txpk' in downlink:
                                    txpk = downlink['txpk']
                                    if 'data' in txpk:
                                        join_accept_b64 = txpk['data']
                                        join_accept = base64.b64decode(join_accept_b64)
                                        print(f"Join Accept (hex): {join_accept.hex().upper()}")
                                        print(f"Transmission frequency: {txpk.get('freq', 'N/A')} MHz")
                                        print(f"Transmission power: {txpk.get('powe', 'N/A')} dBm")
                                        
                            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                                print(f"Error parsing downlink JSON: {e}")
                        
                        break
                        
            except socket.timeout:
                print("No downlink received within timeout")
                break
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

def continuous_pull_data():
    """Continuously send PULL_DATA like a real gateway"""
    print("Starting continuous PULL_DATA simulation...")
    
    while True:
        try:
            version = 2
            token = int(time.time()) & 0xFFFF  # Use timestamp as token
            packet_type = 0x02  # PULL_DATA
            gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
            
            packet = struct.pack('<BHB', version, token, packet_type) + gateway_eui
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            sock.sendto(packet, ('localhost', 1700))
            
            # Check for responses
            try:
                while True:
                    response, addr = sock.recvfrom(1024)
                    
                    if len(response) >= 4:
                        resp_type = response[3]
                        
                        if resp_type == 0x04:  # PULL_ACK
                            print(".", end="", flush=True)  # Heartbeat indicator
                        elif resp_type == 0x03:  # PULL_RESP
                            print(f"\n🎉 DOWNLINK RECEIVED: {response.hex()}")
                            
                            # Parse the downlink
                            if len(response) > 4:
                                try:
                                    json_data = response[4:].decode('utf-8')
                                    downlink = json.loads(json_data)
                                    
                                    if 'txpk' in downlink and 'data' in downlink['txpk']:
                                        join_accept_b64 = downlink['txpk']['data']
                                        join_accept = base64.b64decode(join_accept_b64)
                                        print(f"Join Accept: {join_accept.hex().upper()}")
                                        print("✅ Join Accept successfully queued for transmission!")
                                        return  # Exit after receiving downlink
                                        
                                except Exception as e:
                                    print(f"Error parsing downlink: {e}")
                            
            except socket.timeout:
                pass  # Normal - no downlink available
                
            sock.close()
            time.sleep(10)  # Wait 10 seconds before next PULL_DATA (like real gateways)
            
        except KeyboardInterrupt:
            print("\nStopping continuous PULL_DATA...")
            break
        except Exception as e:
            print(f"\nError in continuous PULL_DATA: {e}")
            time.sleep(5)

if __name__ == "__main__":
    print("Enhanced LoRaWAN Server Test Client")
    print("=" * 40)
    
    # Step 1: Send Join Request
    send_join_request()
    print()
    
    # Wait a moment for server processing#!/usr/bin/env python3
"""
Enhanced UDP client to test the LoRaWAN server with realistic gateway behavior
"""

import socket
import struct
import json
import base64
import time
import threading

def create_join_request():
    """Create a realistic LoRaWAN Join Request"""
    # Use the DevEUI from the example device in the server
    app_eui = bytes.fromhex("FEDCBA9876543210")  # Little endian in packet
    dev_eui = bytes.fromhex("EFCDAB8967452301")  # Little endian in packet  
    dev_nonce = bytes.fromhex("ABCD")
    
    # MHDR for Join Request
    mhdr = 0x00  # Join Request
    
    # Build Join Request: MHDR + AppEUI + DevEUI + DevNonce + MIC
    join_request = bytes([mhdr]) + app_eui + dev_eui + dev_nonce + bytes(4)  # 4-byte placeholder MIC
    
    return join_request

def send_join_request():
    """Send a Join Request via PUSH_DATA"""
    version = 2
    token = 0x1234
    packet_type = 0x00  # PUSH_DATA
    gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    # Create Join Request
    join_request = create_join_request()
    join_request_b64 = base64.b64encode(join_request).decode()
    
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
            "size": len(join_request),
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
        print("Sending Join Request to LoRaWAN server...")
        print(f"DevEUI: {join_request[9:17][::-1].hex().upper()}")  # Reverse for display
        print(f"AppEUI: {join_request[1:9][::-1].hex().upper()}")   # Reverse for display
        
        sock.sendto(packet, ('localhost', 1700))
        
        # Wait for ACK
        response, addr = sock.recvfrom(1024)
        print(f"Received PUSH_ACK: {response.hex()}")
        
    except socket.timeout:
        print("No response received (timeout)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

def simulate_gateway_pull():
    """Simulate gateway PULL_DATA behavior to receive downlinks"""
    version = 2
    token = 0x5678
    packet_type = 0x02  # PULL_DATA
    gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    
    packet = struct.pack('<BHB', version, token, packet_type) + gateway_eui
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)  # Longer timeout for potential downlink
    
    try:
        print("Sending PULL_DATA (checking for downlinks)...")
        sock.sendto(packet, ('localhost', 1700))
        
        # Wait for response
        while True:
            try:
                response, addr = sock.recvfrom(1024)
                
                if len(response) >= 4:
                    resp_version = response[0]
                    resp_token = struct.unpack('<H', response[1:3])[0]
                    resp_type = response[3]
                    
                    if resp_type == 0x04:  # PULL_ACK
                        print(f"Received PULL_ACK: {response.hex()}")
                    elif resp_type == 0x03:  # PULL_RESP (downlink)
                        print(f"Received PULL_RESP (downlink): {response.hex()}")
                        
                        # Parse JSON payload
                        if len(response) > 4:
                            try:
                                json_data = response[4:].decode('utf-8')
                                downlink = json.loads(json_data)
                                print(f"Downlink payload: {json.dumps(downlink, indent=2)}")
                                
                                # Extract and decode Join Accept
                                if 'txpk' in downlink:
                                    txpk = downlink['txpk']
                                    if 'data' in txpk:
                                        join_accept_b64 = txpk['data']
                                        join_accept = base64.b64decode(join_accept_b64)
                                        print(f"Join Accept (hex): {join_accept.hex().upper()}")
                                        print(f"Transmission frequency: {txpk.get('freq', 'N/A')} MHz")
                                        print(f"Transmission power: {txpk.get('powe', 'N/A')} dBm")
                                        
                            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                                print(f"Error parsing downlink JSON: {e}")
                        
                        break
                        
            except socket.timeout:
                print("No downlink received within timeout")
                break
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

def continuous_pull_data():
    """Continuously send PULL_DATA like a real gateway"""
    print("Starting continuous PULL_DATA simulation...")
    
    while True:
        try:
            version = 2
            token = int(time.time()) & 0xFFFF  # Use timestamp as token
            packet_type = 0x02  # PULL_DATA
            gateway_eui = b'\x01\x02\x03\x04\x05\x06\x07\x08'
            
            packet = struct.pack('<BHB', version, token, packet_type) + gateway_eui
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            sock.sendto(packet, ('localhost', 1700))
            
            # Check for responses
            try:
                while True:
                    response, addr = sock.recvfrom(1024)
                    
                    if len(response) >= 4:
                        resp_type = response[3]
                        
                        if resp_type == 0x04:  # PULL_ACK
                            print(".", end="", flush=True)  # Heartbeat indicator
                        elif resp_type == 0x03:  # PULL_RESP
                            print(f"\n🎉 DOWNLINK RECEIVED: {response.hex()}")
                            
                            # Parse the downlink
                            if len(response) > 4:
                                try:
                                    json_data = response[4:].decode('utf-8')
                                    downlink = json.loads(json_data)
                                    
                                    if 'txpk' in downlink and 'data' in downlink['txpk']:
                                        join_accept_b64 = downlink['txpk']['data']
                                        join_accept = base64.b64decode(join_accept_b64)
                                        print(f"Join Accept: {join_accept.hex().upper()}")
                                        print("✅ Join Accept successfully queued for transmission!")
                                        return  # Exit after receiving downlink
                                        
                                except Exception as e:
                                    print(f"Error parsing downlink: {e}")
                            
            except socket.timeout:
                pass  # Normal - no downlink available
                
            sock.close()
            time.sleep(10)  # Wait 10 seconds before next PULL_DATA (like real gateways)
            
        except KeyboardInterrupt:
            print("\nStopping continuous PULL_DATA...")
            break
        except Exception as e:
            print(f"\nError in continuous PULL_DATA: {e}")
            time.sleep(5)

if __name__ == "__main__":
    print("Enhanced LoRaWAN Server Test Client")
    print("=" * 40)
    
    # Step 1: Send Join Request
    send_join_request()
    print()
    
    # Wait a moment for server processing
    time.sleep(1)
    
    # Step 2: Start continuous PULL_DATA in background
    pull_thread = threading.Thread(target=continuous_pull_data, daemon=True)
    pull_thread.start()
    
    # Wait for potential downlink
    print("Waiting for Join Accept downlink...")
    time.sleep(30)  # Wait up to 30 seconds
    
    print("\nTest completed! Check server logs for Join Accept transmission details.")
    time.sleep(1)
    
    # Step 2: Start continuous PULL_DATA in background
    pull_thread = threading.Thread(target=continuous_pull_data, daemon=True)
    pull_thread.start()
    
    # Wait for potential downlink
    print("Waiting for Join Accept downlink...")
    time.sleep(30)  # Wait up to 30 seconds
    
    print("\nTest completed! Check server logs for Join Accept transmission details.")