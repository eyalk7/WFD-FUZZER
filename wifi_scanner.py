from scapy.all import *
from fuzzer import probe_res_frame

IFACE = "wlx00c0caabd843"
nearby_devices = dict()

class Device():
	def __init__(self, ssid, bssid, src_mac, is_ap):
		self.ssid = ssid
		self.bssid = bssid
		self.src_mac = src_mac
		self.is_ap = is_ap
		
		
def get_specific_dot11elt(pkt, id):
	dot11elt = pkt.getlayer(Dot11Elt)
	while dot11elt and dot11elt.ID != id:
		dot11elt = dot11elt.payload.getlayer(Dot11Elt)
	return dot11elt #might return None if layer doesn't exist. Do we want to handle it?
		

#filter and callback func a bit messy.
#need to decide our goal and refactor accordingly


def packet_filter(pkt):
	if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq):
		ssid = str(pkt.getlayer(Dot11Elt).info)
		#if "DIRECT" in ssid
		dot11_layer = pkt.getlayer(Dot11)
		bssid = dot11_layer.addr3
		src_mac = dot11_layer.addr2
		is_ap = False if pkt.haslayer(Dot11ProbeReq) else True
		device = Device(ssid, bssid, src_mac, is_ap)
		print(ssid, bssid, src_mac, is_ap)
		if device.src_mac not in nearby_devices:
			nearby_devices[device.src_mac] = device
		return True
	return False

def send_probe_response(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		dot11_layer = pkt.getlayer(Dot11)
		src_mac = dot11_layer.addr2
		frame = probe_res_frame(src_mac)
		sendp(frame, iface=IFACE)

		
def scan(pkt_filter, callback, **kwargs):
	print("start scan")
	pkts = sniff(iface=IFACE, prn=callback, lfilter=pkt_filter, **kwargs)
	print("scan completed")
	return pkts

			
