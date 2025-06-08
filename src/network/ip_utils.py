from scapy.all import IP, UDP, Raw, send, fragment

def send_custom_ip_packet(dst_ip: str, data: str, ttl: int = 64, do_not_fragment: bool = True):
    """
    Belirtilen hedefe manuel IP header ayarlarıyla UDP paket gönderir.
    """
    flags = 'DF' if do_not_fragment else 0
    packet = IP(dst=dst_ip, ttl=ttl, flags=flags) / UDP(sport=12345, dport=54321) / Raw(load=data.encode())

    print("[IPUtils] Paket Detayları:")
    packet.show()
    send(packet)

def send_fragmented_packet(dst_ip: str, data: str, mtu: int = 8):
    """
    IP paketini manuel olarak parçalayıp gönderir (fragmentation).
    """
    packet = IP(dst=dst_ip)/UDP(sport=12345, dport=54321)/Raw(load=data.encode())
    fragments = fragment(packet, fragsize=mtu)
    print(f"[IPUtils] {len(fragments)} parçaya bölündü.")
    for i, frag in enumerate(fragments):
        print(f"[IPUtils] Parça {i+1}:")
        frag.show()
        send(frag)

# Örnek kullanım
if __name__ == "__main__":
    destination_ip = "192.168.1.100"

    send_custom_ip_packet(
        dst_ip=destination_ip,
        data="Selam! Bu özel IP header'lı bir UDP paketidir.",
        ttl=128,
        do_not_fragment=True
    )

    send_fragmented_packet(
        dst_ip=destination_ip,
        data="Bu veri çok uzun ve parçalanarak gönderilecek. Test için kullanılıyor." * 3,
        mtu=20
    )