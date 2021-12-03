from scapy.all import *
from binascii import unhexlify

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DIRECT_SSID = "DIRECT-"
WIFI_OUI = unhexlify("506f9a")
OUI_TYPE = {"DIRECT": unhexlify("09"), "DISPLAY": unhexlify("0a")}
DIRECT_ATT = {
    "CAPABILITY": unhexlify("02"),
    "LISTEN_CHANNEL": unhexlify("06"),
    "DEVICE_INFO": unhexlify("0d"),
}
DISPLAY_SE = {"DEVICE_INFO": unhexlify("00")}


def binary_str_to_bytes(s):
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def wifi_direct_ie_header():
    return WIFI_OUI + OUI_TYPE["DIRECT"]


def wifi_direct_capabilities_att(device_capability, group_capability):
    # from right to left: Service Discovery, P2P Client Discoverability, Concurrect Operation,
    # P2P Infrastructure Managed, P2P Device Limit, P2P Invitation Procedure
    device_capability_bitmap = binary_str_to_bytes(device_capability)

    # from right to left: P2P Group Owner, Persistent P2P Group, P2P Group Limit, Intra-BSS Distribution,
    # Cross Connection, Persistent Reconnect, Group Formation, IP Address Allocation
    group_capability_bitmap = binary_str_to_bytes(group_capability)

    content = device_capability_bitmap + group_capability_bitmap

    return DIRECT_ATT["CAPABILITY"] + len(content).to_bytes(2, byteorder="little") + content


def wifi_direct_listen_channel_att():
    country_string = bytes("IL", encoding="utf8") + unhexlify("04")

    operating_class = (81).to_bytes(1)

    channel_number = unhexlify("01")

    content = country_string + operating_class + channel_number

    return DIRECT_ATT["LISTEN_CHANNEL"] + len(content).to_bytes(2, byteorder="little") + content


def wifi_direct_device_info_att(ssid):
    # can be the same as source addr
    p2p_device_addr = unhexlify("060708090a0b")

    # from right to left: Flash, Ethernet, Label, Display, External NFC, Integrated NFC, NFC Interface,
    # PushButton, Keypad
    config_methods = binary_str_to_bytes("0000000000001000")

    primary_device_type_category = unhexlify("0007")

    primary_device_type_oui = unhexlify("0050f200")

    primary_device_type_subcategory = unhexlify("0000")

    number_of_secondary_device_types = unhexlify("00")

    device_name_att_type = unhexlify("1011")

    device_name = bytes(ssid, encoding="utf8")
    
    device_name_len = (len(device_name)).to_bytes(2, byteorder="big")

    content = p2p_device_addr + config_methods + primary_device_type_category
    content += primary_device_type_oui + primary_device_type_subcategory
    content += number_of_secondary_device_types + device_name_att_type
    content += device_name_len + device_name

    return DIRECT_ATT["DEVICE_INFO"] + len(content).to_bytes(2, byteorder="little") + content


# from the captures we got, this is the structure of P2P IEs sent by the source (the phone)
def wifi_direct_ie_src():
    header = wifi_direct_ie_header()

    content = wifi_direct_capabilities_att("00100101", "00000000") + wifi_direct_listen_channel_att()

    return header + content

# from the captures we got, this is the structure of P2P IEs sent by the sink (the computer)
def wifi_direct_ie_sink(ssid):
    header = wifi_direct_ie_header()

    content = wifi_direct_capabilities_att("00100101", "00101011") + wifi_direct_device_info_att(ssid)

    return header + content


def wifi_display_ie_header():
    return WIFI_OUI + OUI_TYPE["DISPLAY"]


def wifi_display_device_info_se(flags, port, throughput):
    # from right to left (total 16 bits):
    # WFD Device Type (2 bits) - 00 src, 01 primary sink, 10 secondary sink, 11 dual role
    # Coupled Sink Operation Support as src - 0 not supported, 1 supported
    # Coupled Sink Operation Support as sink - 0 not supported, 1 supported
    # WFD Session Availability (2 bits) - 00 not available, 01 available
    # Service Discovery Support - 0 not supported, 1 supported
    # Preferred Connectivity - 0 P2P (direct), 1 TDLS
    # Content Protection Support - 0 not supported, 1 supported
    # Time Synchronization Support - 0 not supported, 1 supported
    # Audio un-supported at Primary Sink
    # Audio only support at WFD Source
    # TDLS Persistent Group
    # TDLS Persistent Group Re-invoke
    # Reserved (2 bits) - set to 00
    bitmap = binary_str_to_bytes(flags)

    # Default 7236. TCP port at which the WFD Device listens for
    # RTSP messages. (If a WFD Sink that is transmitting this subelement
    # does not support the RTSP server function, this field is set to all
    # zeros.)
    session_mgmt_port = port.to_bytes(2, byteorder="big")

    # Maximum average throughput capability of the WFD Device
    # represented in multiples of 1Mbps
    max_throughput = throughput.to_bytes(2, byteorder="big")

    content = bitmap + session_mgmt_port + max_throughput

    return (
        DISPLAY_SE["DEVICE_INFO"] + len(content).to_bytes(2, byteorder="big") + content
    )


# all of the WFD IEs in the captures we got contains only the wifi display device info subelement.
# potentially it could contain more / other subelements.
def wifi_display_ie():
    header = wifi_display_ie_header()

    content = wifi_display_device_info_se("0000000000000000", 7236, 3)

    return header + content


def probe_req_frame(source_mac):
    # basic headers
    frame = RadioTap()
    frame /= Dot11(addr1=BROADCAST_MAC, addr2=source_mac, addr3=BROADCAST_MAC)
    frame /= Dot11ProbeReq()
    frame /= Dot11Elt(ID="SSID", info=DIRECT_SSID, len=len(DIRECT_SSID))
    frame /= Dot11EltRates(rates=[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C])

    direct_ie = wifi_direct_ie_src()
    frame /= Dot11Elt(ID=221, info=RawVal(direct_ie), len=len(direct_ie))

    return frame


def probe_res_frame(dest_mac, source_mac = "00:01:02:03:04:05", ssid = "DIRECT-TEST"):
    # basic headers
    frame = RadioTap()
    frame /= Dot11(addr1=dest_mac, addr2=source_mac, addr3=source_mac)
    frame /= Dot11ProbeResp()
    frame /= Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame /= Dot11EltRates(rates=[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C])

    direct_ie = wifi_direct_ie_sink(ssid)
    frame /= Dot11Elt(ID=221, info=RawVal(direct_ie), len=len(direct_ie))

    return frame


if __name__ == "__main__":
    phone_mac = "00:00:00:00:00:00"
    iface = ''

    frame = probe_res_frame(phone_mac)
    # wireshark(frame)
    sendp(frame, iface=iface, inter=0.1, loop=1)
