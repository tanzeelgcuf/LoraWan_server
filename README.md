# LoRaWAN OTAA Server

A Python-based LoRaWAN server that supports Over-The-Air Activation (OTAA) with MikroTik gateways using the Semtech UDP packet forwarder format.

## Features

- 🌐 **UDP Server** - Async UDP server listening on port 1700
- 📱 **Device Registry** - Simple device management system
- 🔐 **OTAA Support** - Complete Over-The-Air Activation implementation
- 🔑 **Cryptographic Operations** - AES-128 encryption for LoRaWAN key derivation
- 🏗️ **Semtech Protocol** - Full support for Semtech UDP packet forwarder format
- 🔍 **Join Request Parsing** - Parse and validate LoRaWAN Join Requests
- ✅ **Join Accept Generation** - Generate proper Join Accept responses
- 📊 **Comprehensive Logging** - Detailed logging for debugging and monitoring

## Architecture

```
┌─────────────────┐    UDP/1700    ┌─────────────────┐    LoRaWAN    ┌─────────────┐
│   MikroTik      │ ──────────────▶│  LoRaWAN OTAA   │ ◀─────────────│   LoRaWAN   │
│   Gateway       │                │     Server      │               │   Device    │
└─────────────────┘                └─────────────────┘               └─────────────┘
```

## Requirements

- Python 3.8+
- cryptography library

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/lorawan-otaa-server.git
   cd lorawan-otaa-server
   ```

2. **Create virtual environment** (recommended)
   ```bash
   python -m venv lorawan-env
   
   # Windows
   lorawan-env\Scripts\activate
   
   # macOS/Linux
   source lorawan-env/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

1. **Configure your devices** in `lorawan_server.py`:
   ```python
   def _load_example_devices(self):
       dev_eui = bytes.fromhex("YOUR_DEVICE_EUI")
       app_eui = bytes.fromhex("YOUR_APP_EUI") 
       app_key = bytes.fromhex("YOUR_APP_KEY")
       
       device = Device(dev_eui=dev_eui, app_eui=app_eui, app_key=app_key)
       self.devices[dev_eui] = device
   ```

2. **Start the server**
   ```bash
   python lorawan_server.py
   ```

3. **Test the server**
   ```bash
   python test_client.py
   ```

## Configuration

### Server Configuration
- **Host**: `0.0.0.0` (all interfaces)
- **Port**: `1700` (standard Semtech UDP forwarder port)
- **NetID**: `000001` (configurable in code)

### Device Configuration
Add your LoRaWAN devices to the device registry with:
- **DevEUI**: 8-byte device identifier
- **AppEUI**: 8-byte application identifier  
- **AppKey**: 16-byte application key for OTAA

### Gateway Configuration
Configure your MikroTik gateway to forward packets to your server:
```
# MikroTik RouterOS configuration example
/iot lora servers add name="custom-server" address=YOUR_SERVER_IP port=1700
```

## Testing

The project includes a test client to verify server functionality:

```bash
python test_client.py
```

**Expected output:**
```
LoRaWAN Server Test Client
==============================
Sending test packet to LoRaWAN server...
Received ACK: 02341201
Sending PULL_DATA packet...
Received PULL_ACK: 02785604
Check your server console for activity!
```

## Protocol Support

### Semtech UDP Protocol
- ✅ PUSH_DATA (0x00) - Uplink packets from gateway
- ✅ PUSH_ACK (0x01) - Acknowledgment for PUSH_DATA
- ✅ PULL_DATA (0x02) - Heartbeat from gateway
- ✅ PULL_ACK (0x04) - Acknowledgment for PULL_DATA
- 🔄 PULL_RESP (0x03) - Downlink packets to gateway (framework ready)
- 🔄 TX_ACK (0x05) - Transmission acknowledgment (framework ready)

### LoRaWAN Message Types
- ✅ Join Request (0x00) - Full parsing and validation
- ✅ Join Accept (0x01) - Generation and encryption
- 🔄 Data messages (0x02-0x05) - Framework ready for extension

## Code Structure

```
lorawan-otaa-server/
├── lorawan_server.py      # Main server implementation
├── test_client.py         # UDP test client
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── .gitignore           # Git ignore rules
```

### Key Classes

- **`LoRaWANServer`** - Main server class handling UDP communication
- **`DeviceRegistry`** - Device management and storage
- **`SemtechProtocol`** - Semtech UDP packet forwarder protocol handler
- **`LoRaWANPacketParser`** - LoRaWAN packet parsing and generation
- **`LoRaWANCrypto`** - Cryptographic operations for key derivation

## Logging

The server provides comprehensive logging at different levels:

```python
# Set logging level in lorawan_server.py
logging.basicConfig(level=logging.DEBUG)  # Verbose
logging.basicConfig(level=logging.INFO)   # Standard
```

**Log output example:**
```
2025-06-02 20:06:29,071 - INFO - Loaded example device: DevEUI=0123456789ABCDEF
2025-06-02 20:06:29,071 - INFO - Starting LoRaWAN server on 0.0.0.0:1700
2025-06-02 20:06:29,071 - INFO - Server started successfully
2025-06-02 20:06:35,123 - INFO - Received 89 bytes from ('127.0.0.1', 54321)
2025-06-02 20:06:35,126 - INFO - Join Request from DevEUI: EFCDAB8967452301
2025-06-02 20:06:35,127 - INFO - Device EFCDAB8967452301 joined successfully
```

## Security Features

- ✅ **AES-128 Encryption** - Standard LoRaWAN cryptography
- ✅ **Key Derivation** - Proper NwkSKey and AppSKey generation
- ✅ **MIC Validation** - Framework for Message Integrity Check
- ✅ **Secure Random** - Cryptographically secure random number generation

## Extension Points

### Database Integration
Replace the in-memory device registry:
```python
class DatabaseDeviceRegistry(DeviceRegistry):
    def __init__(self, db_connection):
        self.db = db_connection
    
    def get_device(self, dev_eui: bytes) -> Optional[Device]:
        # Database query implementation
        pass
```

### Multiple Gateway Support
The server already tracks gateways and can be extended for:
- Load balancing
- Gateway-specific routing  
- Redundancy handling

### Frame Counter Management
Add frame counter tracking for enhanced security:
```python
@dataclass
class Device:
    # ... existing fields ...
    fcnt_up: int = 0
    fcnt_down: int = 0
```

## Troubleshooting

### Common Issues

**Server won't start on port 1700**
```bash
# Check if port is in use
netstat -an | grep 1700

# Use alternative port
python lorawan_server.py --port 1701
```

**No response from test client**
- Verify server is running
- Check firewall settings
- Ensure correct IP/port configuration

**Device not joining**
- Verify device credentials (DevEUI, AppEUI, AppKey)
- Check device is in registry
- Verify MIC calculation (if implemented)

### Debug Mode
Enable debug logging for detailed packet analysis:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [LoRaWAN Specification](https://lora-alliance.org/wp-content/uploads/2020/11/lorawantm_specification_-v1.0.3.pdf)
- [Semtech UDP Packet Forwarder](https://github.com/Lora-net/packet_forwarder)
- [MikroTik LoRa Documentation](https://help.mikrotik.com/docs/display/ROS/LoRa)

## Roadmap

- [ ] Frame counter validation
- [ ] Downlink message support  
- [ ] Class A/B/C device support
- [ ] Web-based device management
- [ ] Database integration
- [ ] Clustering support
- [ ] Prometheus metrics
- [ ] Docker containerization

---

**Need help?** Open an issue or check the [documentation](https://github.com/yourusername/lorawan-otaa-server/wiki).
