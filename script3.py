from scapy.all import *
import binascii

IFACE = 'wlan0'
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DIRECT_SSID = 'DIRECT-'
WIFI_OUI = binascii.unhexlify('506f9a')
OUI_TYPE = {'P2P': binascii.unhexlify('09'), 'DIRECT': binascii.unhexlify('0a')}
P2P_ATT = {'CAPABILITY': binascii.unhexlify('02'), 'LISTEN_CHANNEL': binascii.unhexlify('06'), 'DEVICE_INFO': binascii.unhexlify('0d')}
PHONE_MAC='4e:66:41:84:3c:1b'


def binary_str_to_bytes(s):
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))

def probe_req_frame(source_mac):
    # basic headers
    frame = RadioTap()/Dot11(addr1=BROADCAST_MAC, addr2=source_mac, addr3=BROADCAST_MAC)/Dot11ProbeReq()
    frame /= Dot11Elt(ID='SSID', info=DIRECT_SSID, len=len(DIRECT_SSID))
    frame /= Dot11EltRates(rates=[0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c])
    
    # P2P Information Element
    p2p_info = WIFI_OUI + OUI_TYPE['P2P']

    # Capabilities
    # from right to left: Service Discovery, P2P Client Discoverability, Concurrect Operation, 
    # P2P Infrastructure Managed, P2P Device Limit, P2P Invitation Procedure
    device_capability_bitmap = binary_str_to_bytes('00000001')
    # from right to left: P2P Group Owner, Persistent P2P Group, P2P Group Limit, Intra-BSS Distribution,
    # Cross Connection, Persistent Reconnect, Group Formation, IP Address Allocation
    group_capability_bitmap = binary_str_to_bytes('00000000')
    capability_att_len = (len(device_capability_bitmap) + len(group_capability_bitmap)).to_bytes(2, byteorder='little')
    p2p_info += P2P_ATT['CAPABILITY'] + capability_att_len + device_capability_bitmap + group_capability_bitmap

    # Listen Channel
    country_string = bytes('IL', encoding='utf8') + binascii.unhexlify('04')
    operating_class = (81).to_bytes(1)
    channel_number = binascii.unhexlify('01')
    listen_channel_att_len = (len(country_string) + len(operating_class) + len(channel_number)).to_bytes(2, byteorder='little')
    p2p_info += P2P_ATT['LISTEN_CHANNEL'] + listen_channel_att_len + country_string + operating_class + channel_number

    frame /= Dot11Elt(ID=221, info=RawVal(p2p_info), len=len(p2p_info))

    return frame
    
def probe_res_frame(dest_mac):    
    ssid = 'DIRECT-TEST' 
    source_mac = '00:01:02:03:04:05'

    # basic headers
    frame = RadioTap()/Dot11(addr1=dest_mac, addr2=source_mac, addr3=source_mac)/Dot11ProbeResp()
    frame /= Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    frame /= Dot11EltRates(rates=[0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c])

    # P2P Information Element
    p2p_info = WIFI_OUI + OUI_TYPE['P2P']

    # Capabilities
    # from right to left: Service Discovery, P2P Client Discoverability, Concurrect Operation, 
    # P2P Infrastructure Managed, P2P Device Limit, P2P Invitation Procedure
    device_capability_bitmap = binary_str_to_bytes('00000001')
    # from right to left: P2P Group Owner, Persistent P2P Group, P2P Group Limit, Intra-BSS Distribution,
    # Cross Connection, Persistent Reconnect, Group Formation, IP Address Allocation
    group_capability_bitmap = binary_str_to_bytes('00000000')
    capability_att_len = (len(device_capability_bitmap) + len(group_capability_bitmap)).to_bytes(2, byteorder='little')
    p2p_info += P2P_ATT['CAPABILITY'] + capability_att_len + device_capability_bitmap + group_capability_bitmap
    
    # Device Info
    p2p_device_addr = binascii.unhexlify('060708090a0b')   # actually can be the same as source addr
    # from right to left: Flash, Ethernet, Label, Display, External NFC, Integrated NFC, NFC Interface,
    # PushButton, Keypad
    config_methods = binary_str_to_bytes('0000000000001000')
    primary_device_type_category = binascii.unhexlify('0007')
    primary_device_type_oui = binascii.unhexlify('0050f200')
    primary_device_type_subcategory = binascii.unhexlify('0000')
    number_of_secondary_device_types = binascii.unhexlify('00')
    device_name_att_type = binascii.unhexlify('1011')
    device_name = bytes(ssid, encoding='utf8')
    device_name_len = (len(device_name)).to_bytes(2, byteorder='big')

    device_info = p2p_device_addr + config_methods + primary_device_type_category 
    device_info += primary_device_type_oui + primary_device_type_subcategory + number_of_secondary_device_types
    device_info += device_name_att_type + device_name_len + device_name
    device_info_att_len = (len(device_info)).to_bytes(2, byteorder='little')
    p2p_info += P2P_ATT['DEVICE_INFO'] + device_info_att_len + device_info

    frame /= Dot11Elt(ID=221, info=RawVal(p2p_info), len=len(p2p_info))

    return frame

if __name__ == "__main__":
	frame = probe_res_frame(PHONE_MAC)
	# wireshark(frame)
	sendp(frame, iface=IFACE, inter=0.1, loop=1)
