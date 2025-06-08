# Secure File Transfer System

This project implements a secure file transfer system with low-level network protocol manipulation, encryption, and performance analysis capabilities.

[Youtube Presentation](https://www.youtube.com/watch?v=91Btj7m8nYY)

## Features

- Secure file transfer with AES/RSA encryption
- Manual IP packet manipulation and fragmentation
- Network performance analysis
- Security analysis and attack simulation
- Client authentication
- Data integrity verification

## Requirements

- Python 3.8+
- Wireshark (for packet analysis)
- iPerf3 (for bandwidth testing)
- tc (traffic control, for network condition simulation)

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install system tools (on macOS):
```bash
brew install iperf3
brew install wireshark
```

## Project Structure

- `src/`
  - `client.py` - Client implementation
  - `server.py` - Server implementation
  - `crypto/` - Encryption and security modules
  - `network/` - Network manipulation modules
  - `analysis/` - Performance analysis tools

## Usage

1. Start the server:
```bash
sudo python src/server.py
```

2. Run the client:
```bash
python src/client.py [file_to_transfer]
```

## Security Features

- AES-256 encryption for file contents
- RSA-2048 for key exchange
- SHA-256 for integrity verification
- Client authentication using digital certificates

## Network Analysis

The project includes tools for:
- Latency measurement
- Bandwidth testing
- Packet loss simulation
- Network congestion analysis 
