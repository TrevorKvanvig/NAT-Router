#!/usr/bin/env python3
import random
from typing import Tuple
from threading import Thread
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
from scapy.layers.inet import TCP, IP, Ether, ICMP

PRIVATE_IFACE = "eth0"
PRIVATE_IP = "10.0.0.2"

PUBLIC_IFACE = "eth1"
PUBLIC_IP = "172.16.20.2"

FILTER = "icmp or tcp port 80"

class NATTable:
    def __init__(self):
        # NAT translation table
        self.data = {}
    
    def _random_id(self):
        return random.randint(30001, 65535)

    def set(self, ip_src, id_src) -> Tuple[str, int]:
        # Create a new random port for each NEW connection else return saved data if source ip and id if found
        # Set WAN side mapping PUBLIC_IP, random_id [range 30,000 - 65,535]

        new_ip_src = PUBLIC_IP
        if (ip_src, id_src) in self.data:
            new_id_src = self.data[(ip_src, id_src)][1]
        else:
            rand = self._random_id()
            while (new_ip_src, rand) in list(self.data.values()):
                rand = self._random_id()
            new_id_src = rand
            self.data[(ip_src, id_src)] = (new_ip_src, new_id_src)

        return new_ip_src, new_id_src

    def get(self, ip_dst, id_dst) -> Tuple[str, int]:
        # Get LAN side mapping ip_src and id_src
        t = list(self.data.keys())[list(self.data.values()).index((ip_dst, id_dst))]
        ip_src = t[0]
        id_src = t[1]

        return ip_src, id_src


icmp_mapping = NATTable()
tcp_mapping = NATTable()

def process_pkt_private(pkt: Packet):   

    print("received pkt from private interface", pkt.sniffed_on, pkt.summary())

    if pkt.sniffed_on == PRIVATE_IFACE:
        if "10.0.0" not in pkt[IP].src:
            return

        pkt[Ether].src      # accessing a field in the Ether Layer

        # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L502
        pkt[IP].src         # accessing a field in the IP Layer

        try:
            pkt[ICMP].id    # accessing a field in the ICMP Layer, will fail in a TCP packet
    
            pkt[TCP].sport  # accessing a field in the TCP Layer, will fail in a ICMP packet
        except:
            pass


        # Stack a new packet
        # IP(src="xxx.xxx.xxx.xxx", dst="xxx.xxx.xxx.xxx", ttl=???) / ptk[TCP or ICMP, depends on pkt]
        if ICMP in pkt:
            print('\tICMP Packet captured on private interface')
            # icmp does not handle ports
            # src, id = icmp_mapping.set(src, id)
            src, id = icmp_mapping.set(pkt[IP].src, pkt[ICMP].id)
            new_pkt = IP(src=src, dst=pkt[IP].dst)/pkt[ICMP]
            new_pkt[ICMP].id = id
            new_pkt[ICMP].chksum = None

        elif TCP in pkt:
            print('\tTCP Packet captured on private interface')
            src, port = tcp_mapping.set(pkt[IP].src, pkt[TCP].sport)
            new_pkt = IP(src=src, dst=pkt[IP].dst)/pkt[TCP]
            new_pkt[TCP].sport = port
            new_pkt[TCP].chksum = None
            

        # create a new pkt depending on what is being requested
        
        new_pkt.show()
        send(new_pkt, iface=PUBLIC_IFACE, verbose=False)


def process_pkt_public(pkt: Packet):

    print("received pkt from public interface", pkt.sniffed_on, pkt.summary())
    if pkt.sniffed_on == PUBLIC_IFACE:
        if pkt[IP].src == PUBLIC_IP:
            return # skip unecessary packets

        pkt[Ether].src      # accessing a field in the Ether Layer,
        # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L502
        pkt[IP].src         # accessing a field in the IP Layer

        try:
            pkt[ICMP].id    # accessing a field in the ICMP Layer, will fail in a TCP packet
            pkt[TCP].sport  # accessing a field in the TCP Layer, will fail in a ICMP packet
        except:
            pass

        # https://scapy.readthedocs.io/en/latest/usage.html#stacking-layers
        # Stack a new packet
        # IP(src="xxx.xxx.xxx.xxx", dst="xxx.xxx.xxx.xxx", ttl=???) / ptk[TCP or ICMP, depends on pkt]

        if ICMP in pkt:
            print('\tICMP Packet captured on public interface')
            dst, id = icmp_mapping.get(pkt[IP].dst, pkt[ICMP].id)
            new_pkt = IP(src=pkt[IP].src, dst=dst)/pkt[ICMP]
            new_pkt[ICMP].id = id
            new_pkt[ICMP].chksum = None

        elif TCP in pkt:
            print('\tTCP Packet captured on public interface')
            dst, port = tcp_mapping.get(pkt[IP].dst, pkt[TCP].dport)
            new_pkt = IP(src=pkt[IP].src, dst=dst)/pkt[TCP]
            new_pkt[TCP].dport = port
            new_pkt[TCP].chksum = None

        send(new_pkt, iface=PRIVATE_IFACE, verbose=False)
        #pass

def private_listener():
    print("sniffing packets on the private interface")
    sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter=FILTER)


def public_listener():
    print("sniffing packets on the public interface")
    sniff(prn=process_pkt_public, iface=PUBLIC_IFACE, filter=FILTER)


def main():
    thread1 = Thread(target=private_listener)
    thread2 = Thread(target=public_listener)

    print("starting multiple sniffing threads...")
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()


main()