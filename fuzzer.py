#This will be our final file

import sys
from scapy.all import *
from packets import *

PHONE_MAC = "00:00:00:00:00:01"
DIRECT_SSID = "DIRECT-"

class Fuzzer():
	def __init__(self, iface, sta_mac=PHONE_MAC, ap_mac=None):
		self.sta_mac = sta_mac
		self.ap_mac = ap_mac
		self.iface = iface


	def _send_req(self, frame, repeats = 5):
		"""
		sends a probe request in a loop until we get a response and returns the response
		"""
		response = None
		while not response and repeats > 0:
			repeats -= 1
			ans, unans = srp(frame, iface=self.iface, inter=0.5, timeout=0.5)
			ans.summary()
			unans.summary()
			if ans:
				response = ans[0][1] #list of answers. each answer is a tuple
		return response

	def send_probe_req(self, ssid, config_methods, pass_id):
		frame = create_probe_req(self.sta_mac, ssid, config_methods, pass_id) 
		return self._send_req(frame)

	def send_prov_disc_req(self, dst_mac):
		frame = create_prov_disc_req(self.sta_mac, dst_mac)
		return self._send_req(frame, repeats=1)

	def send_auth_req(self, dst_mac):
		frame = create_auth_req(self.sta_mac, dst_mac) 
		return self._send_req(frame, repeats=1)
	
	def send_asso_req(self, dst_mac, ssid):
		frame = create_asso_req(self.sta_mac, dst_mac, ssid)
		return self._send_req(frame, repeats=1)

	
	
	
	
if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("use: sudo python3 fuzzer.py <INTERFACE_NAME>")
		quit()
	
	fuzzer = Fuzzer(sys.argv[1])

	probe_res = fuzzer.send_probe_req(DIRECT_SSID, "0100001111011000", "0000")

	interface_p2p_addr = probe_res.addr2
	device_p2p_addr = get_device_p2p_addr(probe_res)
	sink_ssid = probe_res.info

	if device_p2p_addr == None:
		print("unable to read device P2P address from probe response.")
		quit()		

	prov_res = fuzzer.send_prov_disc_req(device_p2p_addr)
	
	probe_res = fuzzer.send_probe_req(sink_ssid, "0011000101001000", "0004")

	auth_res = fuzzer.send_auth_req(interface_p2p_addr)

	asso_res = fuzzer.send_asso_req(interface_p2p_addr, sink_ssid)

	# after this need to add WPS packages
	
	
	
	
