from scapy.all import IP, Raw, send, sniff
from scapy.layers.inet import TCP
import struct
from typing import List, Tuple
import time

class PacketManager:
    MAX_PAYLOAD_SIZE = 1400

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.sequence_number = 0

    def fragment_data(self, data: bytes) -> List[bytes]:
        """Fragment data into smaller chunks"""
        return [data[i:i + self.MAX_PAYLOAD_SIZE]
                for i in range(0, len(data), self.MAX_PAYLOAD_SIZE)]

    def create_packet(self, payload: bytes, fragment_offset: int = 0,
                     flags: int = 0, ttl: int = 64) -> IP:
        """Create an IP packet with custom headers"""
 
        ip_packet = IP(
            src=self.src_ip,
            dst=self.dst_ip,
            flags=flags,
            frag=fragment_offset,
            ttl=ttl
        )

        tcp_packet = TCP(
            sport=self.src_port,
            dport=self.dst_port,
            seq=self.sequence_number,
            flags='PA'
        )

        packet = ip_packet / tcp_packet / Raw(load=payload)
        

        del packet[IP].chksum
        packet = packet.__class__(bytes(packet))
        
        return packet

    def send_packets(self, packets: List[IP]) -> None:
        """Send a list of packets"""
        for packet in packets:
            send(packet, verbose=False)
            time.sleep(0.001) 

    def calculate_checksum(self, header: bytes) -> int:
        """Calculate IP header checksum"""
        if len(header) % 2 == 1:
            header += b'\0'
        
        words = struct.unpack('!%dH' % (len(header) // 2), header)
        checksum = sum(words)
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF

    def reassemble_fragments(self, fragments: List[Tuple[int, bytes]]) -> bytes:
        """Reassemble fragments into original data"""

        sorted_fragments = sorted(fragments, key=lambda x: x[0])
        

        reassembled = b''.join(fragment[1] for fragment in sorted_fragments)
        return reassembled

    def capture_packets(self, filter_str: str, count: int = 0, timeout: int = None):
        """Capture network packets with specified filter"""
        return sniff(
            filter=filter_str,
            count=count,
            timeout=timeout
        )

    def analyze_latency(self, packet):
        """Calculate packet latency"""

        timestamp = packet.time

        if hasattr(packet, 'answer') and packet.answer:
            rtt = packet.answer.time - timestamp
            return rtt
        return None

    def measure_bandwidth(self, packet_size: int, duration: float) -> float:
        """Measure bandwidth by sending packets and calculating throughput"""
        start_time = time.time()
        bytes_sent = 0
        
        while time.time() - start_time < duration:
            payload = b'X' * packet_size
            packet = self.create_packet(payload)
            send(packet, verbose=False)
            bytes_sent += len(packet)
            time.sleep(0.001)
        
        total_time = time.time() - start_time
        bandwidth = (bytes_sent * 8) / (total_time * 1000000)  # Mbps
        return bandwidth 