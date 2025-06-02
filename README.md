# LoraWan_server

# Custom LoRaWAN Server (OTAA, Python)

## Features

- Supports OTAA JoinRequest and JoinAccept
- Works with MikroTik or Semtech UDP packet forwarders
- MIC validation and DevNonce protection
- Hardcoded DevAddr and static response (extendable)

## Setup

```bash
pip install -r requirements.txt
python main.py
```

## Configure Your LoRaWAN Node

- DevEUI: `0004A30B001C0530`
- JoinEUI: `70B3D57ED003001C`
- AppKey: `0102030405060708090A0B0C0D0E0F10`

## Gateway Setup

Point your MikroTik UDP forwarder to this machine’s IP at port 1700.
