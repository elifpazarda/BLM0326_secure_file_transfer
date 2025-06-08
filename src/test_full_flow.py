import time
from analysis.perf_tools import run_ping, run_iperf3_client
from client import SecureFileClient
from network.nack_udp import run_nack_udp_client
import hashlib
import os

SERVER_IP = "127.0.0.1"
TEST_FILE = "./testfile.txt"
LOG_FILE = "test_log.txt"

def log(message):
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        while chunk := f.read(1024):
            h.update(chunk)
    return h.hexdigest()

def main():
    open(LOG_FILE, "w").close()
    log("=== Uçtan Uca Test Başladı ===")


    log("\n[1] Ping Testi:")
    ping_result = run_ping(SERVER_IP)
    log(ping_result)


    log("\n[2] iPerf3 Testi:")
    iperf_result = run_iperf3_client(SERVER_IP)
    log(iperf_result)


    log("\n[3] TCP Dosya Gönderimi:")
    client = SecureFileClient(SERVER_IP)
    if not client.connect():
        log(" Sunucuya bağlanılamadı.")
        return
    if not client.send_file(TEST_FILE):
        log(" TCP üzerinden dosya gönderimi başarısız.")
        client.close()
        return
    log(" TCP dosya gönderimi başarılı.")
    client.close()

 
    log("\n[4] UDP (NACK) ile Dosya Gönderimi:")
    try:
        run_nack_udp_client(TEST_FILE, SERVER_IP)
        log(" UDP (NACK) dosya gönderimi başarılı.")
    except Exception as e:
        log(f" UDP gönderim hatası: {e}")


    log("\n[5] SHA-256 Doğrulama:")
    original_hash = sha256sum(TEST_FILE)
    received_tcp = "recv_" + os.path.basename(TEST_FILE)
    received_udp = "./received_output.txt"

    if os.path.exists(received_tcp):
        tcp_hash = sha256sum(received_tcp)
        log(f"TCP Hash eşleşmesi: {'' if tcp_hash == original_hash else '❌'}")
    else:
        log(" TCP ile alınan dosya bulunamadı.")

    if os.path.exists(received_udp):
        udp_hash = sha256sum(received_udp)
        log(f"UDP Hash eşleşmesi: {'' if udp_hash == original_hash else '❌'}")
    else:
        log(" UDP ile alınan dosya bulunamadı.")

    log("\n=== Test Tamamlandı ===")

if __name__ == "__main__":
    main()