import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
from client import SecureFileClient
from network.nack_udp import run_nack_udp_client
from network.ip_utils import send_custom_ip_packet
from cryptoutils.rsa_utils import encrypt_key_with_rsa

from analysis.perf_tools import run_ping, run_iperf3_client

class FileTransferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Transfer Client")
        master.geometry("500x500")

        self.server_ip = tk.StringVar(value="127.0.0.1")
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.filepath = tk.StringVar()
        self.use_udp = tk.BooleanVar()

        tk.Label(master, text="Server IP:").pack()
        tk.Entry(master, textvariable=self.server_ip).pack()

        tk.Label(master, text="Username:").pack()
        tk.Entry(master, textvariable=self.username).pack()

        tk.Label(master, text="Password:").pack()
        tk.Entry(master, textvariable=self.password, show="*").pack()

        tk.Button(master, text="Select File", command=self.select_file).pack(pady=5)
        self.file_label = tk.Label(master, text="No file selected")
        self.file_label.pack()

        tk.Checkbutton(master, text="Use UDP", variable=self.use_udp).pack()
        tk.Button(master, text="Send File", command=self.send_file_thread).pack(pady=5)
        tk.Button(master, text="Send with UDP (NACK)", command=self.send_nack_thread).pack(pady=5)
        tk.Button(master, text="Send Raw IP Packet", command=self.send_raw_packet).pack(pady=5)

        tk.Button(master, text="Ping Test", command=self.run_ping_thread).pack(pady=5)
        tk.Button(master, text="iPerf3 Test", command=self.run_iperf_thread).pack(pady=5)

        self.status = tk.Label(master, text="", fg="blue", wraplength=450, justify="left")
        self.status.pack(pady=5)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.filepath.set(path)
            self.file_label.config(text=os.path.basename(path))

    def send_file_thread(self):
        threading.Thread(target=self.send_file).start()

    def send_file(self):
        ip = self.server_ip.get()
        user = self.username.get()
        pwd = self.password.get()
        path = self.filepath.get()
        udp = self.use_udp.get()

        if not (ip and user and pwd and path):
            messagebox.showwarning("Missing Info", "Please fill in all fields and select a file.")
            return

        client = SecureFileClient(ip)

        try:
            original_send_credentials = client.send_credentials
            client.send_credentials = lambda: original_send_credentials(user, pwd)

            aes_key = self.exchange_encrypted_key(ip)
            client.set_aes_key(aes_key)

            if udp:
                success = client.send_file_udp(path)
            else:
                if not client.connect():
                    self.status.config(text="Connection failed", fg="red")
                    return
                success = client.send_file(path)
        except Exception as e:
            self.status.config(text=f"Error: {e}", fg="red")
            return
        finally:
            client.close()

        if success:
            self.status.config(text="File sent successfully", fg="green")
        else:
            self.status.config(text="File send failed", fg="red")

    def send_nack_thread(self):
        threading.Thread(target=self.send_file_nack).start()

    def send_file_nack(self):
        ip = self.server_ip.get()
        path = self.filepath.get()

        if not (ip and path):
            messagebox.showwarning("Missing Info", "Please enter server IP and select a file.")
            return

        if not os.path.exists(path):
            self.status.config(text="Selected file not found.", fg="red")
            return

        try:
            run_nack_udp_client(path, ip)
            self.status.config(text="File sent with UDP (NACK)", fg="green")
        except Exception as e:
            self.status.config(text=f"NACK Send Error: {e}", fg="red")

    def send_raw_packet(self):
        ip = self.server_ip.get()
        try:
            send_custom_ip_packet(ip, "Raw IP Test from GUI", ttl=64, do_not_fragment=True)
            self.status.config(text="Raw IP packet sent successfully", fg="green")
        except Exception as e:
            self.status.config(text=f"Raw packet error: {e}", fg="red")

    def exchange_encrypted_key(self, ip, rsa_port=6000):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, rsa_port))
        public_key = s.recv(2048)
        s.close()

        encrypted_key = encrypt_key_with_rsa(public_key, os.urandom(16))

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, rsa_port))
        s.sendall(encrypted_key)
        s.close()
        return encrypted_key

    def run_ping_thread(self):
        threading.Thread(target=self.run_ping).start()

    def run_ping(self):
        ip = self.server_ip.get()
        try:
            output = run_ping(ip)
            self.status.config(text=f"[Ping Output]\n{output}", fg="white")
        except Exception as e:
            self.status.config(text=f"Ping error: {e}", fg="red")

    def run_iperf_thread(self):
        threading.Thread(target=self.run_iperf).start()

    def run_iperf(self):
        ip = self.server_ip.get()
        try:
            output = run_iperf3_client(ip)
            self.status.config(text=f"[iPerf3 Output]\n{output}", fg="white")
        except Exception as e:
            self.status.config(text=f"iPerf3 error: {e}", fg="red")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferGUI(root)
    root.mainloop()
