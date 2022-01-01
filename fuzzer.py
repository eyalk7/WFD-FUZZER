# This will be our final file

import sys
from scapy.all import *
from packets import *
from binascii import hexlify, unhexlify
from time import sleep
from random import randbytes

PHONE_MAC = "00:00:00:00:00:01"
DIRECT_SSID = "DIRECT-"


class Fuzzer:
    def __init__(self, iface, sta_mac=PHONE_MAC, ap_mac=None):
        self.sta_mac = sta_mac
        self.ap_mac = ap_mac
        self.iface = iface

    def _send_req(self, frame, repeats=10):
        """
        sends a probe request in a loop until we get a response and returns the response
        """
        response = None
        while not response and repeats > 0:
            repeats -= 1
            ans, unans = srp(
                frame, iface=self.iface, inter=0.02, timeout=0.5, verbose=False
            )
            if ans:
                response = ans[0][1]  # list of answers. each answer is a tuple
        return response

    def send_probe_req(self, ssid, config_methods, pass_id):
        frame = create_probe_req(self.sta_mac, ssid, config_methods, pass_id)
        return self._send_req(frame)

    def send_prov_disc_req(self, dst_mac, dev_name="FUZZER"):
        frame = create_prov_disc_req(self.sta_mac, dst_mac, dev_name)
        return self._send_req(frame)

    def send_auth_req(self, dst_mac):
        frame = create_auth_req(self.sta_mac, dst_mac)
        sendp(frame, iface=self.iface)

    def send_asso_req(self, dst_mac, ssid):
        frame = create_asso_req(self.sta_mac, dst_mac, ssid)
        sendp(frame, iface=self.iface)

    def send_block_ack_req(self, dst_mac):
        frame = create_block_ack_req(self.sta_mac, dst_mac)
        return self._send_req(frame)

    def send_eap(self, dst_mac, phase, id=0):
        frame = create_eap_packet(dst_mac, self.sta_mac, phase, id)
        return self._send_req(frame)


def run_protocol(fuzzer, sink_mac):
    device_p2p_addr = None
    interface_p2p_addr = None
    sink_ssid = None
    while device_p2p_addr == None:
        probe_res = fuzzer.send_probe_req(DIRECT_SSID, "0100001111011000", "0000")

        if probe_res == None:
            continue

        interface_p2p_addr = probe_res.addr2
        sink_ssid = probe_res.info
        device_p2p_addr = get_device_p2p_addr(probe_res)

        if device_p2p_addr != unhexlify(sink_mac):
            print("Found sink ", hexlify(device_p2p_addr))
            device_p2p_addr = None

    fuzzer.send_prov_disc_req(device_p2p_addr)

    while True:
        probe_res = fuzzer.send_probe_req(sink_ssid, "0011000101001000", "0004")
        if get_wps_response_type(probe_res) == 2:
            break

    fuzzer.send_auth_req(interface_p2p_addr)

    fuzzer.send_asso_req(interface_p2p_addr, sink_ssid)

    eap_iden_req = fuzzer.send_eap(interface_p2p_addr, "start")

    print(eap_iden_req)

    fuzzer.send_eap(interface_p2p_addr, "id")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("use: sudo python3 fuzzer.py <INTERFACE_NAME>")
        quit()

    fuzzer = Fuzzer(sys.argv[1])

    # Sink MAC is given here to prevent initiating the protocol with some unknown device
    run_protocol(fuzzer, sink_mac="82c5f27aa0a3")
