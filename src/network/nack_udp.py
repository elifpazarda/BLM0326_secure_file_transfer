import socket
import threading
import time

PACKET_SIZE = 1024
PORT = 5006
ACK_TIMEOUT = 2

def run_nack_udp_server(bind_ip='0.0.0.0', port=PORT):
    """
    UDP sunucu tarafı: Paketleri alır, eksik paketleri NACK ile bildirir.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    print(f"[UDP Server] Dinleniyor: {bind_ip}:{port}")

    received_packets = {}
    expected_total = None

    while True:
        data, addr = sock.recvfrom(PACKET_SIZE + 10)
        parts = data.split(b"|", 2)
        if len(parts) != 3:
            continue

        index, total, payload = int(parts[0]), int(parts[1]), parts[2]
        received_packets[index] = payload
        expected_total = int(total)

        print(f"[UDP Server] Parça {index+1}/{expected_total} alındı.")

        if len(received_packets) == expected_total:
            print("[UDP Server] Tüm veriler alındı. Birleştiriliyor...")
            full_data = b"".join(received_packets[i] for i in range(expected_total))
            with open("received_output.txt", "wb") as f:
                f.write(full_data)
            print("[UDP Server] Dosya yazıldı: received_output.txt")
            break

    missing = [i for i in range(expected_total) if i not in received_packets]
    if missing:
        nack_msg = f"NACK:{','.join(map(str, missing))}".encode()
        sock.sendto(nack_msg, addr)
        print(f"[UDP Server] Eksik parçalar bildirildi: {missing}")

def run_nack_udp_client(file_path, server_ip, port=PORT):
    """
    UDP istemci tarafı: Dosyayı parçalayıp gönderir, NACK alırsa tekrar gönderir.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with open(file_path, "rb") as f:
        data = f.read()

    chunks = [data[i:i + PACKET_SIZE] for i in range(0, len(data), PACKET_SIZE)]
    total = len(chunks)

    def send_chunk(index):
        msg = f"{index}|{total}|".encode() + chunks[index]
        sock.sendto(msg, (server_ip, port))

    for i in range(total):
        send_chunk(i)
        print(f"[UDP Client] Parça {i+1}/{total} gönderildi.")
        time.sleep(0.01)

    sock.settimeout(ACK_TIMEOUT)
    try:
        nack_data, _ = sock.recvfrom(2048)
        if nack_data.startswith(b"NACK:"):
            missing = list(map(int, nack_data.decode().split(":")[1].split(",")))
            print(f"[UDP Client] Eksik parçalar yeniden gönderiliyor: {missing}")
            for idx in missing:
                send_chunk(idx)
    except socket.timeout:
        print("[UDP Client] NACK alınmadı, tüm veriler gönderildi olarak kabul ediliyor.")

if __name__ == "__main__":
    run_nack_udp_server()