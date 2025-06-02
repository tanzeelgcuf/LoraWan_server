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
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
        # Example device - replace with your actual devices
        dev_eui = bytes.fromhex("0123456789ABCDEF")
        app_eui = bytes.fromhex("FEDCBA9876543210")
        app_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        
        device = Device(dev_eui=dev_eui, app_eui=app_eui, app_key=app_key)
        self.devices[dev_eui] = device
        logger.info(f"Loaded example device: DevEUI={dev_eui.hex().upper()}")
    
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
                          dl_settings: int = 0, rx_delay: int = 1) -> bytes:
        """Create LoRaWAN Join Accept"""
        # MHDR
        mhdr = (LoRaWANPacketParser.JOIN_ACCEPT << 5)
        
        # Join Accept payload (without MIC)
        payload = (app_nonce + net_id + dev_addr + 
                  bytes([dl_settings, rx_delay]))
        
        # For simplicity, using dummy MIC (in real implementation, calculate proper MIC)
        mic = bytes(4)
        
        return bytes([mhdr]) + payload + mic

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
            
            # Generate Join Accept
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
                app_nonce, self.net_id, dev_addr
            )
            
            # Send downlink (simplified - would need proper gateway communication)
            logger.info(f"Device {dev_eui.hex().upper()} joined successfully")
            logger.info(f"DevAddr: {dev_addr.hex().upper()}")
            
        except Exception as e:
            logger.error(f"Error handling Join Request: {e}")

class UDPServerProtocol:
    """UDP server protocol handler"""
    
    def __init__(self, server: LoRaWANServer):
        self.server = server
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP packets"""
        try:
            packet_type, token, payload = SemtechProtocol.parse_packet(data)
            
            # Send ACK
            if packet_type in [SemtechProtocol.PUSH_DATA, SemtechProtocol.PULL_DATA]:
                ack = SemtechProtocol.create_ack(packet_type, token)
                self.transport.sendto(ack, addr)
            
            # Handle packet
            if packet_type == SemtechProtocol.PUSH_DATA and payload:
                self.server.handle_push_data(addr, token, payload)
            elif packet_type == SemtechProtocol.PULL_DATA:
                logger.debug(f"PULL_DATA from {addr}")
            
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