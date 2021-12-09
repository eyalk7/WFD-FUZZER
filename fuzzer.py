#This will be our final file

from scapy.all import *
from packets import *


PHONE_MAC = "00:00:00:00:00:01"
IFACE = "wlan0"


class Fuzzer():
	def __init__(self, iface=IFACE, sta_mac=PHONE_MAC, ap_mac=None):
		self.sta_mac = sta_mac
		self.ap_mac = ap_mac


	def _send_req(self, frame):
		"""
		sends a probe request in a loop until we get a response and returns the response
		"""
		response = None
		while not response:
			ans, unans = srp(frame, iface=IFACE, inter=0.1, timeout=0.1)
			if ans:
				response = ans[0][1] #list of answers. each answer is a tuple
		return response

	def send_probe_req(self):
		frame = create_probe_req(self.sta_mac) 
		return self._send_req(frame)

	def send_auth_req(self, dst_mac):
		frame = create_auth_req(self.sta_mac, dst_mac) 
		return self._send_req(frame)
	
	def send_asso_req(self, dst_mac, ssid):
		frame = create_asso_req(self.sta_mac, dst_mac, ssid)
		return self._send_req(frame)

	
	
	
	
if __name__ == "__main__":
	fuzzer = Fuzzer()
	probe_res = fuzzer.send_probe_req()
	dst_mac = probe_res.addr2
	ssid = probe_res.info
	auth_res = fuzzer.send_auth_req(dst_mac) #currently fails here. get de-auth right after auth
	asso_res = fuzzer.send_asso_req(dst_mac, ssid)
	
	
	
	
