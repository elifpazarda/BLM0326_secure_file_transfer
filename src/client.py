import socket
import sys
import os
import argparse
import hashlib
import time
from cryptoutils.encryption import CryptoManager
from network.packet import PacketManager
from network.ip_utils import send_custom_ip_packet  # <-- Scapy modülü import edildi

CHUNK_SIZE = 1024
UDP_TIMEOUT = 3
UDP_RETRIES = 3
UDP_PORT = 5005

def calculate_sha256(data: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

class SecureFileClient:
    def send_credentials(self, username=None, password=None):
        try:
            if username is None or password is None:
                username = input("Username: ")
                password = input("Password: ")
            credentials = f"{username}:{password}".encode()
            self.client_socket.send(credentials)
            response = self.client_socket.recv(1024)
            return response == b'AUTH_OK'
        except Exception as e:
            print(f"Error sending credentials: {e}")
            return False

    def __init__(self, server_host: str, server_port: int = 12345):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = CryptoManager()
        self.crypto.generate_rsa_keys()
        self.packet_mgr = PacketManager(
            socket.gethostbyname(socket.gethostname()),
            server_host,
            0,
            server_port
        )
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.settimeout(UDP_TIMEOUT)

    def send_test_ip_packet(self, content="Raw IP Packet Test"):
        print(f"[IP TEST] Sending raw IP packet to {self.server_host}...")
        send_custom_ip_packet(self.server_host, content, ttl=64, do_not_fragment=True)

    def connect(self) -> bool:
        try:
            self.client_socket.connect((self.server_host, self.server_port))
            if not self.send_credentials():
                print("❌ Authentication failed (username/password)")
                return False
            return self.authenticate()
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def authenticate(self) -> bool:
        try:
            server_public_key = self.client_socket.recv(2048)
            self.client_socket.send(self.crypto.public_key.export_key())
            encrypted_challenge = self.client_socket.recv(2048)
            challenge = self.crypto.decrypt_aes_key(encrypted_challenge)
            self.client_socket.send(challenge)
            return True
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    def send_file(self, filename: str) -> bool:
        if not os.path.exists(filename):
            print(f"File not found: {filename}")
            return False
        try:
            self.client_socket.send(b'SEND')
            time.sleep(0.3)
            with open(filename, 'rb') as f:
                file_data = f.read()
            file_size = len(file_data)
            metadata = f"{os.path.basename(filename)}|{file_size}".encode()
            self.client_socket.send(metadata)
            sha256_hash = calculate_sha256(file_data).encode()
            fragments = self.packet_mgr.fragment_data(file_data)
            for fragment in fragments:
                encrypted_fragment = self.crypto.encrypt_data(fragment)
                self.client_socket.send(encrypted_fragment)
            self.client_socket.send(sha256_hash)
            response = self.client_socket.recv(1024)
            if response == b'SUCCESS':
                print(f" File {filename} sent successfully")
                return True
            else:
                print(f" Error from server: {response.decode()}")
                return False
        except Exception as e:
            print(f" Error sending file: {e}")
            return False

    def send_file_udp(self, filename: str) -> bool:
        if not os.path.exists(filename):
            print(f"File not found: {filename}")
            return False
        with open(filename, 'rb') as f:
            file_data = f.read()
        file_hash = calculate_sha256(file_data).encode()
        fragments = [file_data[i:i+CHUNK_SIZE] for i in range(0, len(file_data), CHUNK_SIZE)]
        total = len(fragments)
        print(f"Sending {filename} in {total} UDP fragments...")
        self.udp_socket.sendto(f"META|{os.path.basename(filename)}|{total}".encode(), (self.server_host, UDP_PORT))
        time.sleep(0.1)
        for i, fragment in enumerate(fragments):
            packet = f"{i}".zfill(4).encode() + b"|" + fragment
            self.udp_socket.sendto(packet, (self.server_host, UDP_PORT))
        time.sleep(0.1)
        self.udp_socket.sendto(b"HASH|" + file_hash, (self.server_host, UDP_PORT))
        retries = 0
        while retries < UDP_RETRIES:
            try:
                nack_data, _ = self.udp_socket.recvfrom(2048)
                if nack_data.startswith(b"NACK"):
                    missing = nack_data.decode().split("|")[1:]
                    print(f"Retransmitting {len(missing)} fragments (try {retries + 1})...")
                    for idx in missing:
                        i = int(idx)
                        packet = f"{i}".zfill(4).encode() + b"|" + fragments[i]
                        self.udp_socket.sendto(packet, (self.server_host, UDP_PORT))
                    retries += 1
                else:
                    break
            except socket.timeout:
                break
        print("UDP file transfer complete.")
        return True

    def close(self):
        self.client_socket.close()
        self.udp_socket.close()

def main():
    parser = argparse.ArgumentParser(description='Secure File Transfer Client (TCP/UDP)')
    parser.add_argument('server', help='Server hostname or IP address')
    parser.add_argument('--port', type=int, default=12345, help='Server TCP port')
    parser.add_argument('--send', help='File to send')
    parser.add_argument('--udp', action='store_true', help='Use UDP instead of TCP')
    parser.add_argument('--testip', action='store_true', help='Send raw IP test packet')
    args = parser.parse_args()

    client = SecureFileClient(args.server, args.port)

    if args.testip:
        client.send_test_ip_packet()
        sys.exit(0)

    if not args.udp and not client.connect():
        print("Failed to connect to server")
        sys.exit(1)

    try:
        if args.send:
            if args.udp:
                client.send_file_udp(args.send)
            else:
                client.send_file(args.send)
    finally:
        client.close()

if __name__ == "__main__":
    main()
