# This will be our final file

import sys
from scapy.all import *
from packets import *
from binascii import hexlify, unhexlify
from enum import Enum
from random import randbytes

PHONE_MAC = "00:00:00:00:00:01"
DIRECT_SSID = "DIRECT-"

class States(Enum):
    PROBE_1 = 1
    PROBE_2 = 2
    PROV = 3
    AUTH = 4
    ASSO = 5
    EAPOL = 6
    DONE = 7


class Fuzzer:
    def __init__(self, iface, sta_mac=PHONE_MAC):
        self.device_name = 'FUZZER'
        self.sta_mac = sta_mac
        self.iface = iface
        self.target_ap_mac = None
        self.ssid = None
        self.target_p2p_mac = None
        self.sn = 0
        self.state = None
        self.packet_creators = {
            States.PROBE_1 : self.create_probe_req,
            States.PROBE_2 : self.create_probe_req,
            States.PROV : self.create_prov_disc_req,
            States.AUTH : self.create_auth_req,
            States.ASSO : self.create_asso_req,
            States.EAPOL: self.create_eap_packet,
            States.DONE: quit
            }

    def _send_req(self, frame, recv=True, repeats=10):
        """
        sends a probe request in a loop until we get a response and return the response
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

    def create_probe_req(self):
        if self.state == States.PROBE_1:
            config_methods = "0100001111011000"
            pass_id = "0000"
        elif self.state == States.PROBE_2:
            config_methods = "0011000101001000"
            pass_id = "0004"
        else:
            raise ValueError
        frame = create_probe_req(self.sta_mac, self.ssid, config_methods, pass_id)
        return frame

    def create_prov_disc_req(self):
        frame = create_prov_disc_req(self.sta_mac, self.target_p2p_mac, self.device_name)
        return frame

    def create_auth_req(self):
        frame = create_auth_req(self.sta_mac, self.target_ap_mac)
        return frame

    def create_asso_req(self):
        frame = create_asso_req(self.sta_mac, self.target_ap_mac, self.ssid)
        return frame

    def create_block_ack_req(self):
        frame = create_block_ack_req(self.sta_mac, self.target_ap_mac)
        return frame

    def create_eap_packet(self):
        frame = create_eap_packet(self.sta_mac, self.target_ap_mac, phase="start", id=0)
        return frame

    def fuzz_dev_name(self):
        device_name = randbytes(15)
        frame = create_prov_disc_req(self.sta_mac, self.target_p2p_mac, device_name)
        return frame
    
    def fuzz_it(self):
        for state in States:
            self.state = state
            frame = self.packet_creators[state]()
            response = self._send_req(frame)
            if state == States.PROBE_1:
                self.target_p2p_mac = get_device_p2p_addr(response)
                self.target_ap_mac = response.addr2
                self.ssid = response.info
            elif state == States.PROBE_2:
                while get_wps_response_type(response) != 2:
                    response = self._send_req(frame)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("use: sudo python3 fuzzer.py <INTERFACE_NAME>")
        quit()

    fuzzer = Fuzzer(sys.argv[1])
    #TODO: better to show a menu and let user choose type of fuzzing and set it inside the fuzzer
    fuzzer.packet_creators[States.PROV] = fuzzer.fuzz_dev_name
    for i in range(256):
        fuzzer.fuzz_it()



        
        