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
    DONE = 7

PACKET_CREATORS = {
            State.PROBE_1 : create_probe_req,
            State.PROBE_2 : create_probe_req,
            State.PROV : create_prov_disc_req,
            State.AUTH : create_auth_req,
            State.ASSO : create_asso_req,
            State.EAPOL: create_eap_packet
}

class Fuzzer:
    def __init__(self, iface, sta_mac=PHONE_MAC, ap_mac=None, to_fuzz=None, packet_creators=PACKET_CREATORS):
        self.sta_mac = sta_mac
        self.target_ap_mac = ap_mac
        self.iface = iface
        self.ssid = None
        self.state = None
        self.to_fuzz = to_fuzz
        self.sn = 0
        self.packet_creators = packet_creators

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

    
    def random_fuzz(self):
        #TODO: avoid code duplication of pkt creation and sending
        self.state = State.PROBE_1
        frame = self.packet_creators[self.state](self.sta_mac, DIRECT_SSID, "0100001111011000", "0000")
        if self.to_fuzz and self.state in self.to_fuzz:
            fuzz(frame)
        response = self._send_req(frame)
        device_p2p_addr = get_device_p2p_addr(response)
        if device_p2p_addr == None:
            print("unable to read device P2P address from probe response.")
            quit()

        self.target_ap_mac = response.addr2
        self.ssid = response.info

        self.state = State.PROV
        frame = self.packet_creators[self.state](self.sta_mac, device_p2p_addr)
        if self.to_fuzz and self.state in self.to_fuzz:
            fuzz(frame)
        response = self._send_req(frame)

        self.state = State.PROBE_2
        frame = self.packet_creators[self.state](self.sta_mac, self.ssid, "0011000101001000", "0004")
        if self.to_fuzz and self.state in self.to_fuzz:
            fuzz(frame)
        while True:
            response = self._send_req(frame)
            if get_wps_response_type(response) == 2:
                break

        self.state = State.AUTH
        frame = self.packet_creators[self.state](self.sta_mac, self.target_ap_mac)
        if self.to_fuzz and self.state in self.to_fuzz:
            fuzz(frame)
        response = self._send_req(frame)

        self.state = State.ASSO
        frame = self.packet_creators[self.state](self.sta_mac, self.target_ap_mac, self.ssid)
        if self.to_fuzz and self.state in self.to_fuzz:
            fuzz(frame)
        response = self._send_req(frame)
        
        
        self.state = State.DONE