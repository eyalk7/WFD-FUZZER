# This will be our final file

import sys
from scapy.all import *
from packets import *
from utils import *
from enum import Enum
from random import randbytes

PHONE_MAC = "00:00:00:00:00:01"
DIRECT_SSID = "DIRECT-"

class States(Enum):
    PROBE_1 = 1
    PROV = 2
    PROBE_2 = 3
    AUTH_1 = 4
    ASSO_1 = 5
    EAPOL = 6
    EAP_IDEN = 7
    EAP_M1 = 8
    EAP_M3 = 9
    EAP_M5 = 10
    EAP_M7 = 11
    EAP_DONE = 12
    DISASSO = 13
    AUTH_2 = 14
    ASSO_2 = 15
    KEY2 = 16
    KEY4 = 17
    DONE = 18


class Fuzzer:
    def __init__(self, iface, sta_mac=PHONE_MAC, target_ap_mac = None, starting_seq_num = 1001):
        self.device_name = bytes('FUZZER', encoding="utf8")
        self.sta_mac = sta_mac
        self.iface = iface
        self.target_ap_mac = target_ap_mac
        self.ssid = DIRECT_SSID
        self.target_p2p_mac = None
        self.sn = 0
        self.state = None
        self.seq_num = starting_seq_num
        self.packet_creators = {
            States.PROBE_1 : (self.create_probe_req, {}),
            States.PROV : (self.create_prov_disc_req, {"device_name": self.device_name}),
            States.PROBE_2 : (self.create_probe_req, {}),
            States.AUTH_1 : (self.create_auth_req, {}),
            States.ASSO_1 : (self.create_asso_req, {"device_name": self.device_name}),
            States.EAPOL : (self.create_eap_start_packet, {}),
            States.EAP_IDEN : (self.create_eap_iden_packet, {}),
            States.EAP_M1 : (self.create_eap_m1_packet, {}),
            States.EAP_M3 : (self.create_eap_m3_packet, {}),
            States.EAP_M5 : (self.create_eap_m5_packet, {}),
            States.EAP_M7 : (self.create_eap_m7_packet, {}),
            States.EAP_DONE : (self.create_eap_done_packet,{}),
            # States.DISASSO : _
            # States.AUTH_2 : _
            # States.ASSO_2 : _
            # States.KEY2 : _
            # States.KEY4 : _
            States.DONE : (quit, {})
            }

    def _send_req(self, frame, recv=True, repeats=10):
        """
        sends a request in a loop until we get a response or we iterate a number equal to repeats and return the response
        """
        if recv:
            response = None
            while not response and repeats > 0:
                repeats -= 1
                ans, unans = srp(frame, iface=self.iface, inter=0.02, timeout=0.5)
                ans.summary()
                unans.summary()
                if ans:
                    response = ans[0][1]  # list of answers. each answer is a tuple
        else:
            sendp(frame)

        return response

    def create_probe_req(self, **kwargs):
        if self.state == States.PROBE_1:
            config_methods = "0100001111011000"
            pass_id = "0000"
        elif self.state == States.PROBE_2:
            config_methods = "0011000101001000"
            pass_id = "0004"
        else:
            raise ValueError
        frame = create_probe_req(self.sta_mac, self.ssid, config_methods, pass_id, create_seq_num(self.seq_num), **kwargs)
        return frame

    def create_prov_disc_req(self, **kwargs):
        frame = create_prov_disc_req(self.sta_mac, self.target_p2p_mac, create_seq_num(self.seq_num), **kwargs)
        return frame

    def create_auth_req(self, **kwargs):
        frame = create_auth_req(self.sta_mac, self.target_ap_mac, create_seq_num(self.seq_num), **kwargs)
        return frame

    def create_asso_req(self, **kwargs):
        frame = create_asso_req(self.sta_mac, self.target_ap_mac, self.ssid, create_seq_num(self.seq_num), **kwargs)
        return frame

    def create_block_ack_req(self, **kwargs):
        frame = create_block_ack_req(self.sta_mac, self.target_ap_mac, create_seq_num(self.seq_num), **kwargs)
        return frame

    def create_eap_start_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="start", id=0, **kwargs)
        return frame

    def create_eap_iden_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="iden", id=0, **kwargs)
        return frame

    def create_eap_m1_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="m1", id=0, **kwargs)
        return frame

    def create_eap_m3_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="m3", id=0, **kwargs)
        return frame

    def create_eap_m5_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="m5", id=0, **kwargs)
        return frame

    def create_eap_m7_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="m7", id=0, **kwargs)
        return frame 

    def create_eap_done_packet(self, **kwargs):
        frame = create_eap_packet(self.target_ap_mac, self.sta_mac, create_seq_num(self.seq_num), phase="done", id=0, **kwargs)
        return frame
    
    def set_fuzzed_value(self, state, new_values):
        self.packet_creators[state][1].update(new_values)

    
    def fuzz_it(self):
        for state in self.packet_creators.keys():
            print("starting state: ", state)
            self.state = state
            func, kwargs = self.packet_creators[state]
            frame = func(**kwargs)
            response = self._send_req(frame)
            if state == States.PROBE_1:
                reps = 10
                while reps and (response == None or (self.target_ap_mac != None and self.target_ap_mac != response.addr2)):
                    # Got wrong device, try again
                    response = self._send_req(frame)
                    reps -= 1
                self.target_ap_mac = response.addr2
                self.target_p2p_mac = get_device_p2p_addr(response)                
                self.ssid = response.info
            elif state == States.PROBE_2:
                reps = 10
                while reps and get_wps_response_type(response) != 2:
                    response = self._send_req(frame)
            elif state == States.EAPOL:
                print(response)
                quit()
            self.seq_num += 1

        
    def fuzz_length(self, state, field, starting_length, iterations=10, step=1):  
        macs = mac_iterator(max_iterations=iterations)
        while iterations:
            fuzzer.sta_mac = next(macs)
            fuzzer.set_fuzzed_value(state, {field: starting_length})
            fuzzer.fuzz_it()
            starting_length += step
            iterations -= 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("use: sudo python3 fuzzer.py <INTERFACE_NAME> <TARGET_AP_MAC:optional>")
        quit()

    target_ap_mac = None
    if len(sys.argv) == 3:
        target_ap_mac = sys.argv[2]

    fuzzer = Fuzzer(sys.argv[1], target_ap_mac=target_ap_mac)
    
    #fuzz length of SSID in first probe request (length only, ssid is the same)
    #fuzzer.set_fuzzed_value(States.PROBE_1, {'ssid_len': 100})
    
    #fuzz device name in provision request:
    fuzzer.fuzz_length(States.PROV, "dev_name_len", 10)
