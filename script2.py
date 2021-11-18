from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

netSSID = 'DIRECT-AAA'       #Network name here
iface = 'wlan0'         #Interface name here
broadcast='ff:ff:ff:ff:ff:ff'
sourceId = '33:33:33:33:33:33'
BSSid = '33:33:33:33:33:33'

dot11 = Dot11(type=0, subtype=8, addr1=broadcast,
addr2=sourceId, addr3=BSSid)
beacon = Dot11Beacon()
essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
asd = Dot11Elt(ID=221 ,info=netSSID, len=len(netSSID))
frame = RadioTap()/dot11/beacon/essid/asd

sendp(frame, iface=iface, inter=0.100, loop=1)