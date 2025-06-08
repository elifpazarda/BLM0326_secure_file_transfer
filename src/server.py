import socket
import sys
import threading
from typing import Dict, Tuple
import os
import hashlib
import time
from cryptoutils.encryption import CryptoManager
from network.packet import PacketManager

CHUNK_SIZE = 1024
UDP_PORT = 5005
UDP_TIMEOUT = 5

USER_CREDENTIALS = {
    "admin": "1234",
    "elif": "guvenli",
    "burak": "network"
}

def verify_credentials(client_socket: socket.socket) -> bool:
    try:
        credentials = client_socket.recv(1024).decode()
        username, password = credentials.split(":")
        if USER_CREDENTIALS.get(username) == password:
            client_socket.send(b'AUTH_OK')
            return True
        else:
            client_socket.send(b'AUTH_FAIL')
            return False
    except Exception as e:
        print(f"Credential verification error: {e}")
        client_socket.send(b'AUTH_ERROR')
        return False

def calculate_sha256(data: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

class SecureFileServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 12345):
        self.host = host
        self.port = port
        self.crypto = CryptoManager()
        self.clients: Dict[str, bytes] = {}
        self.crypto.generate_rsa_keys()
        self.crypto.generate_aes_key()

 
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)


        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, UDP_PORT))
        self.udp_socket.settimeout(UDP_TIMEOUT)

    
        self.udp_fragments = {}
        self.udp_expected = 0
        self.udp_filename = "received_udp_file.txt"
        self.udp_client = None
        self.udp_hash = None

    def start(self):
        print(f"TCP server listening on {self.host}:{self.port}")
        threading.Thread(target=self.listen_udp, daemon=True).start()

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_handler.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            self.server_socket.close()

    def listen_udp(self):
        print(f"UDP server listening on {self.host}:{UDP_PORT}")
        while True:
            try:
                data, addr = self.udp_socket.recvfrom(2048)
                self.udp_client = addr

                if data.startswith(b"META"):
                    _, fname, total = data.decode().split("|")
                    self.udp_filename = f"recv_{fname}"
                    self.udp_expected = int(total)
                    self.udp_fragments = {}
                    continue

                elif data.startswith(b"HASH|"):
                    self.udp_hash = data[5:].decode()
                    continue

                seq, fragment = data.split(b"|", 1)
                index = int(seq)
                self.udp_fragments[index] = fragment

            except socket.timeout:
                self.handle_udp_timeout()

    def handle_udp_timeout(self):
        print("UDP timeout. Checking for missing fragments...")
        if self.udp_expected == 0 or not self.udp_client:
            return
        missing = [str(i) for i in range(self.udp_expected) if i not in self.udp_fragments]
        if missing:
            nack = "NACK|" + "|".join(missing)
            self.udp_socket.sendto(nack.encode(), self.udp_client)
        elif len(self.udp_fragments) == self.udp_expected:
            with open(self.udp_filename, "wb") as f:
                for i in range(self.udp_expected):
                    f.write(self.udp_fragments[i])
            print(f"UDP file saved as {self.udp_filename}")
            with open(self.udp_filename, "rb") as f:
                file_data = f.read()
            calc_hash = calculate_sha256(file_data)
            if calc_hash == self.udp_hash:
                print("✅ UDP SHA-256 matched.")
            else:
                print("❌ UDP SHA-256 mismatch.")
            self.udp_expected = 0
            self.udp_hash = None

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        print(f"New TCP connection from {address[0]}:{address[1]}")
        try:
            if not verify_credentials(client_socket):
                print("Login failed for", address[0])
                client_socket.close()
                return  

            if not self.authenticate_client(client_socket, address[0]):
                print("Authentication failed for", address[0])
                client_socket.close()
                return  

            packet_mgr = PacketManager(self.host, address[0], self.port, address[1])

            while True:
                command = client_socket.recv(1024).decode()
                if not command:
                    break

                if command.startswith('SEND'):
                    self.handle_file_receive(client_socket, packet_mgr)
                elif command.startswith('GET'):
                    self.handle_file_send(client_socket, packet_mgr, command[4:])
                else:
                    print(f"Unknown command: {command}")

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def authenticate_client(self, client_socket: socket.socket, client_ip: str) -> bool:
        try:
            print(f"[AUTH] Sending server public key to {client_ip}")
            client_socket.send(self.crypto.public_key.export_key())

            client_public_key = client_socket.recv(2048)
            if not client_public_key:
                print("[AUTH] No public key received from client.")
                return False
            self.clients[client_ip] = client_public_key

            self.crypto.generate_aes_key()

            encrypted_challenge = self.crypto.encrypt_aes_key(client_public_key)
            client_socket.send(encrypted_challenge)

            response = client_socket.recv(2048)
            if response != self.crypto.aes_key:
                print("[AUTH] Challenge mismatch.")
                return False

            print("[AUTH] Client authenticated successfully.")
            return True
        except Exception as e:
            print(f"[AUTH ERROR] {e}")
            return False

    def handle_file_receive(self, client_socket: socket.socket, packet_mgr: PacketManager):
        try:
            metadata = client_socket.recv(1024).decode().split('|')
            filename, file_size = metadata[0], int(metadata[1])
            filename = "recv_" + filename
            received_data = b''
            received_size = 0
            while received_size < file_size:
                fragment = client_socket.recv(packet_mgr.MAX_PAYLOAD_SIZE)
                if not fragment:
                    break
                decrypted_fragment = self.crypto.decrypt_data(fragment)
                received_data += decrypted_fragment
                received_size += len(decrypted_fragment)
            received_hash = client_socket.recv(64).decode()
            calculated_hash = calculate_sha256(received_data)
            if received_hash != calculated_hash:
                client_socket.send(b'HASH_MISMATCH')
                print("❌ SHA-256 mismatch!")
                return
            with open(filename, 'wb') as f:
                f.write(received_data)
            client_socket.send(b'SUCCESS')
        except Exception as e:
            print(f"Error receiving file: {e}")
            client_socket.send(b'ERROR')

    def handle_file_send(self, client_socket: socket.socket, packet_mgr: PacketManager, filename: str):
        try:
            if not os.path.exists(filename):
                client_socket.send(b'FILE_NOT_FOUND')
                return
            with open(filename, 'rb') as f:
                file_data = f.read()
            file_size = len(file_data)
            metadata = f"{filename}|{file_size}".encode()
            client_socket.send(metadata)
            sha256_hash = calculate_sha256(file_data).encode()
            fragments = packet_mgr.fragment_data(file_data)
            for fragment in fragments:
                encrypted_fragment = self.crypto.encrypt_data(fragment)
                client_socket.send(encrypted_fragment)
            client_socket.send(sha256_hash)
            response = client_socket.recv(1024)
            if response != b'SUCCESS':
                print(f"Error sending file: {response.decode()}")
        except Exception as e:
            print(f"Error sending file: {e}")
            client_socket.send(b'ERROR')

def main():
    if os.geteuid() != 0:
        print("This program requires root privileges to manipulate network packets.")
        print("Please run with sudo.")
        sys.exit(1)

    server = SecureFileServer()
    server.start()

if __name__ == '__main__':
    main()
