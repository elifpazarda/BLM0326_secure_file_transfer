import subprocess
import platform
import time

def run_ping(target_ip: str, count: int = 4) -> float:
    print(f"[PING] Measuring RTT to {target_ip}...")
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(['ping', param, str(count), target_ip], stderr=subprocess.STDOUT, universal_newlines=True)
        lines = output.splitlines()
        for line in lines:
            if 'avg' in line or 'Average' in line or 'ms' in line:
                return output
        return output
    except subprocess.CalledProcessError as e:
        return f"[PING ERROR] {e.output}"

def run_iperf3_server():
    print("[IPERF3] Starting iPerf3 server...")
    try:
        subprocess.call(['iperf3', '-s'])
    except FileNotFoundError:
        print("iperf3 not found. Please install it.")

def run_iperf3_client(target_ip: str) -> str:
    print(f"[IPERF3] Running client to {target_ip}...")
    try:
        result = subprocess.check_output(['iperf3', '-c', target_ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"[IPERF3 ERROR] {e.output}"

def simulate_network_conditions(interface='lo0', delay='100ms', loss='5%'):
    print(f"[TC] Simulating delay={delay}, loss={loss} on interface {interface}...")
    try:
        subprocess.run(['sudo', 'tc', 'qdisc', 'add', 'dev', interface, 'root', 'netem',
                        'delay', delay, 'loss', loss], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[TC ERROR] {e}")
