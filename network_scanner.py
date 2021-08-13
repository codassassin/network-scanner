#!/usr/bin/env python

import scapy.all as scapy


class scan:
    def __init__(self):
        self.arp_request = None
        self.broadcast = None
        self.arp_request_broadcast = None
        self.answered_list = None

    def scan(self, ip):
        try:
            print(f"\n[+] Scanning {ip} ...")
            self.arp_request = scapy.ARP(pdst=ip)
            self.broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            self.arp_request_broadcast = self.broadcast / self.arp_request
            self.answered_list = scapy.srp(self.arp_request_broadcast, timeout=1, verbose=False)[0]

            clients_list = []
            for element in self.answered_list:
                client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                clients_list.append(client_dict)
            return clients_list

        except Exception as e:
            print(f"[-] ERROR: {e}")


def print_result(results_list):
    print("IP\t\t\t\t|\tMAC Address\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


if __name__ == "__main__":
    ip = input("[:] Input the IP range to scan (e.g. 192.168.43.1/24): \n\t\t-> ")
    scanner = scan()
    scan_result = scanner.scan(str(ip))
    print_result(scan_result)
