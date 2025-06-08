import matplotlib.pyplot as plt
import re

def plot_ping(output: str):
    times = re.findall(r'time=([\d\.]+) ms', output)
    times = [float(t) for t in times]

    plt.figure(figsize=(8,4))
    plt.plot(times, marker='o', linestyle='-', color='blue')
    plt.title('Ping RTT Zaman Grafiği')
    plt.xlabel('Paket Numarası')
    plt.ylabel('RTT (ms)')
    plt.grid(True)
    plt.show()

def plot_iperf3(output: str):
    intervals = re.findall(r'\\[\\s\\d\\.\\-]+ sec', output)
    bandwidths = re.findall(r'([\d\.]+) [GMK]?bits/sec', output)
    bandwidths = [float(b) for b in bandwidths]

    plt.figure(figsize=(8,4))
    plt.plot(bandwidths, marker='o', linestyle='-', color='green')
    plt.title('iPerf3 Bant Genişliği Grafiği')
    plt.xlabel('Zaman Aralığı')
    plt.ylabel('Bant Genişliği (Gbit/s)')
    plt.grid(True)
    plt.show()
