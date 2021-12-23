# This will be our final file

import sys
from scapy.all import *
from packets import *
from binascii import hexlify, unhexlify
from enum import Enum

PHONE_MAC = "00:00:00:00:00:01"
DIRECT_SSID = "DIRECT-"

class State(Enum):
    PROBE_1 = 1
    PROBE_2 = 2
    PROV = 3
    AUTH = 4
    ASSO = 5
    EAPOL = 6

class Fuzzer:
    def __init__(self, iface, sta_mac=PHONE_MAC, ap_mac=None, to_fuzz=None):
        self.sta_mac = sta_mac
        self.target_ap_mac = ap_mac
        self.iface = iface
        self.ssid = None
        self.state = None
        self.to_fuzz = to_fuzz
        self.sn = 0
        self.packet_creators = {
            State.PROBE_1 : create_probe_req,
            State.PROBE_2 : create_probe_req,
            State.PROV : create_prov_disc_req,
            State.AUTH : create_auth_req,
            State.ASSO : create_asso_req,
            State.EAPOL: create_eap_packet
        }

    def _send_req(self, frame, recv=True, repeats=10):
        """
        sends a probe request in a loop until we get a response and returns the response
        """
        if recv:
            response = None
            while not response and repeats > 0:
                repeats -= 1
                ans, unans = srp(frame, iface=self.iface, inter=0.2, timeout=0.5)
                ans.summary()
                unans.summary()
                if ans:
                    response = ans[0][1]  # list of answers. each answer is a tuple
        else:
            sendp(frame)

        return response

    def send_probe_req(self, ssid, config_methods, pass_id):
        frame = create_probe_req(self.sta_mac, ssid, config_methods, pass_id)
        return self._send_req(frame)

    def send_probe_req_cpy(self, type, ssid, dev_name):
        frame = create_probe_req_cpy(self.sta_mac, type, ssid, dev_name)
        return self._send_req(frame)

    def send_prov_disc_req(self, dst_mac):
        frame = create_prov_disc_req(self.sta_mac, dst_mac)
        return self._send_req(frame)

    def send_prov_disc_req_cpy(self, dst_mac, dev_name):
        frame = create_prov_disc_req_cpy(self.sta_mac, dst_mac, dev_name)
        return self._send_req(frame, repeats=5)

    def send_auth_req(self, dst_mac):
        frame = create_auth_req(self.sta_mac, dst_mac)
        return self._send_req(frame)

    def send_auth_req_cpy(self, dst_mac):
        frame = create_auth_req_cpy(self.sta_mac, dst_mac)
        return self._send_req(frame, repeats=1)

    def send_asso_req(self, dst_mac, ssid):
        frame = create_asso_req(self.sta_mac, dst_mac, ssid)
        return self._send_req(frame)

    def send_asso_req_cpy(self, dst_mac, ssid, dev_name):
        frame = create_asso_req_cpy(self.sta_mac, dst_mac, ssid, dev_name)
        return self._send_req(frame, repeats=1)

    def send_null_cpy(self, dst_mac):
        frame = create_null_cpy(self.sta_mac, dst_mac)
        return self._send_req(frame)

    def send_block_ack_req(self, dst_mac):
        frame = create_block_ack_req(self.sta_mac, dst_mac)
        return self._send_req(frame)

    def send_block_ack_req_cpy(self, dst_mac):
        frame = create_block_ack_req_cpy(self.sta_mac, dst_mac)
        return self._send_req(frame, repeats=1)

    def send_eap(self, dst_mac, phase, id=0):
        frame = create_eap_packet(dst_mac, self.sta_mac, phase, id)
        return self._send_req(frame)

    def send_eap_start_cpy(self, dst_mac):
        frame = create_eap_start_cpy(self.sta_mac, dst_mac)
        return self._send_req(frame)



    
    def random_fuzz():
        self.state = State.PROBE_1
        frame = self.packet_creators[self.state](self.sta_mac, DIRECT_SSID, "0100001111011000", "0000")
        if self.to_fuzz and self.state in to_fuzz:
            fuzz(frame)
        probe_res = self._send_req(frame)
        device_p2p_addr = get_device_p2p_addr(probe_res)
        if device_p2p_addr == None:
            print("unable to read device P2P address from probe response.")
            quit()

        self.target_ap_mac = probe_res.addr2
        self.ssid = probe_res.info

        frame = create_prov_disc_req(self.sta_mac, dst_mac)

    


def regular_protocol(fuzzer):
    probe_res = fuzzer.send_probe_req(DIRECT_SSID, "0100001111011000", "0000")

    interface_p2p_addr = probe_res.addr2
    device_p2p_addr = get_device_p2p_addr(probe_res)
    sink_ssid = probe_res.info

    if device_p2p_addr == None:
        print("unable to read device P2P address from probe response.")
        quit()

    prov_res = fuzzer.send_prov_disc_req(device_p2p_addr)

    while True:
        probe_res = fuzzer.send_probe_req(sink_ssid, "0011000101001000", "0004")
        if get_wps_response_type(probe_res) == 2:
            break

    auth_res = fuzzer.send_auth_req(interface_p2p_addr)

    asso_res = fuzzer.send_asso_req(interface_p2p_addr, sink_ssid)

    # block_ack_res = fuzzer.send_block_ack_req(interface_p2p_addr)

    eap_start_res = fuzzer.send_eap(interface_p2p_addr, "start")

    # eap_id_res = send_eap(interface_p2p_addr, "id")
    # after this need to add WPS packages