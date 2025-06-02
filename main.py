#!/usr/bin/env python3
"""
LoRaWAN OTAA Server Scaffold
Supports Semtech UDP packet forwarder format for MikroTik gateways
"""

import asyncio
import json
import struct
import logging
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Device:
    """Device registry entry"""
    dev_eui: bytes
    app_eui: bytes
    app_key: bytes
    dev_addr: Optional[bytes] = None
    nwk_s_key: Optional[bytes] = None
    app_s_key: Optional[bytes] = None
    joined: bool = False

class DeviceRegistry:
    """Simple device registry"""
    
    def __init__(self):
        self.devices: Dict[bytes, Device] = {}
        self._load_example_devices()
    
    def _load_example_devices(self):
        """Load some example devices for testing"""
        # Example device - matches the test client
        # Note: DevEUI and AppEUI are stored in little endian in LoRaWAN packets
        # but we store them in big endian (normal) format in our registry
        dev_eui = bytes.fromhex("0123456789ABCDEF")  # Big endian format
        app_eui = bytes.fromhex("0123456789ABCDEF")  # Big endian format  
        app_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        
        device = Device(dev_eui=dev_eui, app_eui=app_eui, app_key=app_key)
        self.devices[dev_eui] = device
        logger.info(f"Loaded example device: DevEUI={dev_eui.hex().upper()}")
        
        # Add a second device that matches our test client exactly
        test_dev_eui = bytes.fromhex("0123456789ABCDEF")  # This will match reversed test packet
        test_app_eui = bytes.fromhex("0123456789ABCDEF")
        test_app_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        
        test_device = Device(dev_eui=test_dev_eui, app_eui=test_app_eui, app_key=test_app_key)
        self.devices[test_dev_eui] = test_device
        logger.info(f"Loaded test device: DevEUI={test_dev_eui.hex().upper()}")
    
    def get_device(self, dev_eui: bytes) -> Optional[Device]:
        """Get device by DevEUI"""
        return self.devices.get(dev_eui)
    
    def add_device(self, device: Device):
        """Add device to registry"""
        self.devices[device.dev_eui] = device

class LoRaWANCrypto:
    """LoRaWAN cryptographic operations"""
    
    @staticmethod
    def aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
        """AES-128 encryption"""
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    
    @staticmethod
    def generate_keys(app_key: bytes, app_nonce: bytes, net_id: bytes, dev_nonce: bytes) -> Tuple[bytes, bytes]:
        """Generate NwkSKey and AppSKey"""
        # NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
        nwk_input = bytes([0x01]) + app_nonce + net_id + dev_nonce + bytes(7)
        nwk_s_key = LoRaWANCrypto.aes128_encrypt(app_key, nwk_input)
        
        # AppSKey = aes128_encrypt(AppKey, 0x02 | AppNonce | NetID | DevNonce | pad16)
        app_input = bytes([0x02]) + app_nonce + net_id + dev_nonce + bytes(7)
        app_s_key = LoRaWANCrypto.aes128_encrypt(app_key, app_input)
        
        return nwk_s_key, app_s_key

class SemtechProtocol:
    """Semtech UDP packet forwarder protocol handler"""
    
    # Packet identifiers
    PUSH_DATA = 0x00
    PUSH_ACK = 0x01
    PULL_DATA = 0x02
    PULL_ACK = 0x04
    PULL_RESP = 0x03
    TX_ACK = 0x05
    
    @staticmethod
    def parse_packet(data: bytes) -> Tuple[int, int, Optional[dict]]:
        """Parse Semtech UDP packet"""
        if len(data) < 4:
            raise ValueError("Packet too short")
        
        version = data[0]
        token = struct.unpack('<H', data[1:3])[0]
        packet_type = data[3]
        
        if version != 2:
            raise ValueError(f"Unsupported protocol version: {version}")
        
        payload = None
        if packet_type == SemtechProtocol.PUSH_DATA and len(data) > 12:
            # PUSH_DATA has 8-byte gateway EUI + JSON payload
            try:
                json_data = data[12:].decode('utf-8')
                payload = json.loads(json_data)
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse JSON payload: {e}")
        
        return packet_type, token, payload
    
    @staticmethod
    def create_ack(packet_type: int, token: int) -> bytes:
        """Create ACK packet"""
        ack_type = {
            SemtechProtocol.PUSH_DATA: SemtechProtocol.PUSH_ACK,
            SemtechProtocol.PULL_DATA: SemtechProtocol.PULL_ACK,
        }.get(packet_type)
        
        if ack_type is None:
            raise ValueError(f"No ACK for packet type: {packet_type}")
        
        return struct.pack('<BHB', 2, token, ack_type)
    
    @staticmethod
    def create_pull_resp(token: int, payload: dict) -> bytes:
        """Create PULL_RESP packet with downlink"""
        json_data = json.dumps(payload).encode('utf-8')
        return struct.pack('<BHB', 2, token, SemtechProtocol.PULL_RESP) + json_data

class LoRaWANPacketParser:
    """LoRaWAN packet parser"""
    
    # Message types
    JOIN_REQUEST = 0x00
    JOIN_ACCEPT = 0x01
    UNCONFIRMED_DATA_UP = 0x02
    UNCONFIRMED_DATA_DOWN = 0x03
    CONFIRMED_DATA_UP = 0x04
    CONFIRMED_DATA_DOWN = 0x05
    
    @staticmethod
    def parse_join_request(data: bytes) -> dict:
        """Parse LoRaWAN Join Request"""
        if len(data) < 23:
            raise ValueError("Join Request too short")
        
        # MHDR (1) + AppEUI (8) + DevEUI (8) + DevNonce (2) + MIC (4)
        mhdr = data[0]
        mtype = (mhdr >> 5) & 0x07
        
        if mtype != LoRaWANPacketParser.JOIN_REQUEST:
            raise ValueError(f"Not a Join Request: MType={mtype}")
        
        app_eui = data[1:9][::-1]  # Reverse byte order (little endian)
        dev_eui = data[9:17][::-1]  # Reverse byte order (little endian)
        dev_nonce = data[17:19]
        mic = data[19:23]
        
        return {
            'mtype': mtype,
            'app_eui': app_eui,
            'dev_eui': dev_eui,
            'dev_nonce': dev_nonce,
            'mic': mic
        }
    
    @staticmethod
    def create_join_accept(app_nonce: bytes, net_id: bytes, dev_addr: bytes, 
                          app_key: bytes, dl_settings: int = 0, rx_delay: int = 1) -> bytes:
        """Create LoRaWAN Join Accept (encrypted)"""
        # MHDR
        mhdr = (LoRaWANPacketParser.JOIN_ACCEPT << 5)
        
        # Join Accept payload (without MIC)
        # AppNonce(3) + NetID(3) + DevAddr(4) + DLSettings(1) + RxDelay(1)
        payload = (app_nonce + net_id + dev_addr + 
                  bytes([dl_settings, rx_delay]))
        
        # Calculate MIC over MHDR + DecryptedPayload using AppKey
        # For simplicity, using dummy MIC (in production, implement proper MIC)
        mic = bytes([0x12, 0x34, 0x56, 0x78])  # Placeholder MIC
        
        # Complete unencrypted Join Accept
        join_accept_plain = bytes([mhdr]) + payload + mic
        
        # Encrypt Join Accept payload (not MHDR) using AppKey
        # Note: In LoRaWAN, Join Accept payload is encrypted with AppKey
        encrypted_payload = LoRaWANCrypto.aes128_encrypt(app_key, payload + mic + bytes(1))[:len(payload + mic)]
        
        return bytes([mhdr]) + encrypted_payload

class LoRaWANServer:
    """Main LoRaWAN server class"""
    
    def __init__(self, host='0.0.0.0', port=1700):
        self.host = host
        self.port = port
        self.device_registry = DeviceRegistry()
        self.gateways = {}  # Track connected gateways
        self.net_id = bytes.fromhex("000001")  # Example NetID
    
    async def start(self):
        """Start the UDP server"""
        logger.info(f"Starting LoRaWAN server on {self.host}:{self.port}")
        
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPServerProtocol(self),
            local_addr=(self.host, self.port)
        )
        
        logger.info("Server started successfully")
        return transport
    
    def handle_push_data(self, addr: Tuple[str, int], token: int, payload: dict):
        """Handle PUSH_DATA from gateway"""
        if 'rxpk' in payload:
            for rxpk in payload['rxpk']:
                if 'data' in rxpk:
                    try:
                        # Decode base64 LoRaWAN packet
                        import base64
                        lorawan_data = base64.b64decode(rxpk['data'])
                        self.process_lorawan_packet(addr, rxpk, lorawan_data)
                    except Exception as e:
                        logger.error(f"Error processing LoRaWAN packet: {e}")
    
    def process_lorawan_packet(self, addr: Tuple[str, int], rxpk: dict, data: bytes):
        """Process LoRaWAN packet"""
        try:
            if len(data) == 0:
                return
            
            mtype = (data[0] >> 5) & 0x07
            
            if mtype == LoRaWANPacketParser.JOIN_REQUEST:
                self.handle_join_request(addr, rxpk, data)
            else:
                logger.info(f"Received packet with MType: {mtype}")
                
        except Exception as e:
            logger.error(f"Error processing LoRaWAN packet: {e}")
    
    def handle_join_request(self, addr: Tuple[str, int], rxpk: dict, data: bytes):
        """Handle Join Request"""
        try:
            join_req = LoRaWANPacketParser.parse_join_request(data)
            dev_eui = join_req['dev_eui']
            
            logger.info(f"Join Request from DevEUI: {dev_eui.hex().upper()}")
            
            device = self.device_registry.get_device(dev_eui)
            if not device:
                logger.warning(f"Unknown device: {dev_eui.hex().upper()}")
                return
            
            # Validate MIC (simplified - in production, implement proper MIC validation)
            # For now, we'll assume the device is valid if it's in our registry
            
            # Generate Join Accept parameters
            app_nonce = secrets.token_bytes(3)
            dev_addr = secrets.token_bytes(4)
            
            # Generate session keys
            nwk_s_key, app_s_key = LoRaWANCrypto.generate_keys(
                device.app_key, app_nonce, self.net_id, join_req['dev_nonce']
            )
            
            # Update device
            device.dev_addr = dev_addr
            device.nwk_s_key = nwk_s_key
            device.app_s_key = app_s_key
            device.joined = True
            
            # Create Join Accept
            join_accept = LoRaWANPacketParser.create_join_accept(
                app_nonce, self.net_id, dev_addr, device.app_key
            )
            
            # Send Join Accept downlink to gateway
            self.send_join_accept_downlink(addr, rxpk, join_accept)
            
            logger.info(f"Device {dev_eui.hex().upper()} joined successfully")
            logger.info(f"DevAddr: {dev_addr.hex().upper()}")
            logger.info(f"AppNonce: {app_nonce.hex().upper()}")
            
        except Exception as e:
            logger.error(f"Error handling Join Request: {e}")
    
    def send_join_accept_downlink(self, gateway_addr: Tuple[str, int], rxpk: dict, join_accept: bytes):
        """Send Join Accept as downlink through gateway"""
        try:
            import base64
            
            # Calculate transmit time (1 second after receive)
            rx_timestamp = rxpk.get('tmst', 0)
            tx_timestamp = rx_timestamp + 1000000  # 1 second delay
            
            # Use RX1 window parameters (same frequency, but could be different)
            tx_freq = rxpk.get('freq', 868.1)
            
            # For RX1, use same datarate as uplink, but can be adjusted
            rx_datarate = rxpk.get('datr', 'SF7BW125')
            
            # Create downlink packet structure
            downlink_packet = {
                "txpk": {
                    "imme": False,        # Not immediate
                    "tmst": tx_timestamp, # Transmit timestamp
                    "freq": tx_freq,      # Frequency
                    "rfch": 0,           # RF chain
                    "powe": 14,          # Power (dBm)
                    "modu": "LORA",      # Modulation
                    "datr": rx_datarate, # Data rate
                    "codr": "4/5",       # Coding rate
                    "ipol": True,        # Polarization inversion for downlink
                    "size": len(join_accept),
                    "data": base64.b64encode(join_accept).decode('utf-8')
                }
            }
            
            # Store the downlink for gateway PULL_DATA response
            self.store_downlink_for_gateway(gateway_addr, downlink_packet)
            
            logger.info(f"Join Accept queued for transmission on {tx_freq} MHz")
            logger.debug(f"Join Accept payload: {join_accept.hex().upper()}")
            
        except Exception as e:
            logger.error(f"Error preparing Join Accept downlink: {e}")
    
    def store_downlink_for_gateway(self, gateway_addr: Tuple[str, int], packet: dict):
        """Store downlink packet for gateway"""
        if not hasattr(self, 'pending_downlinks'):
            self.pending_downlinks = {}
        
        # Use gateway IP as key (in production, use gateway EUI)
        gateway_key = gateway_addr[0]
        
        if gateway_key not in self.pending_downlinks:
            self.pending_downlinks[gateway_key] = []
        
        self.pending_downlinks[gateway_key].append(packet)
        logger.debug(f"Stored downlink for gateway {gateway_key}")
    
    def get_pending_downlink(self, gateway_addr: Tuple[str, int]) -> Optional[dict]:
        """Get pending downlink for gateway"""
        if not hasattr(self, 'pending_downlinks'):
            return None
            
        gateway_key = gateway_addr[0]
        
        if gateway_key in self.pending_downlinks and self.pending_downlinks[gateway_key]:
            return self.pending_downlinks[gateway_key].pop(0)
        
        return None

class UDPServerProtocol:
    """UDP server protocol handler"""
    
    def __init__(self, server: LoRaWANServer):
        self.server = server
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP packets"""
        logger.info(f"Received {len(data)} bytes from {addr}")
        try:
            packet_type, token, payload = SemtechProtocol.parse_packet(data)
            logger.info(f"Packet type: {packet_type}, Token: {token:04X}")
            
            # Send ACK
            if packet_type in [SemtechProtocol.PUSH_DATA, SemtechProtocol.PULL_DATA]:
                ack = SemtechProtocol.create_ack(packet_type, token)
                self.transport.sendto(ack, addr)
                logger.info(f"Sent ACK for packet type {packet_type}")
            
            # Handle packet
            if packet_type == SemtechProtocol.PUSH_DATA and payload:
                logger.info(f"Processing PUSH_DATA payload: {payload}")
                self.server.handle_push_data(addr, token, payload)
            elif packet_type == SemtechProtocol.PULL_DATA:
                logger.debug(f"PULL_DATA from {addr}")
                
                # Check for pending downlinks
                downlink = self.server.get_pending_downlink(addr)
                if downlink:
                    # Send PULL_RESP with downlink
                    pull_resp = SemtechProtocol.create_pull_resp(token, downlink)
                    self.transport.sendto(pull_resp, addr)
                    logger.info(f"Sent PULL_RESP with downlink to {addr}")
            
        except Exception as e:
            logger.error(f"Error handling packet from {addr}: {e}")

async def main():
    """Main function"""
    server = LoRaWANServer()
    transport = await server.start()
    
    try:
        # Keep server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())