from scapy.all import *

iface="wlx00c0caabd843"

unique_devices = set()


def expand(pkt):
#returns a generator. use list(expand(pkt)) or for p in expand(pkt)
    yield type(pkt)
    while pkt.payload:
        pkt = pkt.payload
        yield type(pkt)

def packet_handler(pkt):
	if pkt.haslayer(Dot11Beacon):
		dot11_layer = pkt.getlayer(Dot11)
		if dot11_layer.addr2 and (dot11_layer.addr2 not in unique_devices):
			essid = essid = pkt.getlayer(Dot11Elt).info
			unique_devices.add((dot11_layer.addr2, essid))

print("start sniff")
sniff(iface=iface, count=1000, prn=packet_handler)
print("end sniff, devices found:")
print(unique_devices)
			
