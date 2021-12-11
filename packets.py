from scapy.all import *
from binascii import hexlify, unhexlify

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
WIFI_OUI = unhexlify("506f9a")
WPS_OUI = unhexlify("0050f2")
OUI_TYPE = {
    "DIRECT": unhexlify("09"),
    "DISPLAY": unhexlify("0a"),
    "WPS": unhexlify("04"),
}
DIRECT_ATT = {
    "CAPABILITY": unhexlify("02"),
    "LISTEN_CHANNEL": unhexlify("06"),
    "DEVICE_INFO": unhexlify("0d"),
}
DISPLAY_SE = {"DEVICE_INFO": unhexlify("00")}
WPS_ATT = {
    "VERSION": unhexlify("104a"),
    "REQUEST_TYPE": unhexlify("103a"),
    "CONFIG_METHODS": unhexlify("1008"),
    "UUID_E": unhexlify("1047"),
    "DEV_TYPE": unhexlify("1054"),
    "RF_BANDS": unhexlify("103c"),
    "ASSOC_STATE": unhexlify("1002"),
    "CONF_ERROR": unhexlify("1009"),
    "PASS_ID": unhexlify("1012"),
    "MANUFACTURER": unhexlify("1021"),
    "MODEL_NAME": unhexlify("1023"),
    "MODEL_NUM": unhexlify("1024"),
    "DEV_NAME": unhexlify("1011"),
    "VERSION_2": unhexlify("1049"),
}


def binary_str_to_bytes(s):
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def mac_addr_to_hex(addr):
    return "".join([c if (i + 1) % 3 else "" for i, c in enumerate(addr)])


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

    return (
        DIRECT_ATT["CAPABILITY"]
        + len(content).to_bytes(2, byteorder="little")
        + content
    )


def wifi_direct_listen_channel_att():
    country_string = bytes("IL", encoding="utf8") + unhexlify("04")

    operating_class = (81).to_bytes(1, byteorder="little")

    channel_number = unhexlify("01")

    content = country_string + operating_class + channel_number

    return (
        DIRECT_ATT["LISTEN_CHANNEL"]
        + len(content).to_bytes(2, byteorder="little")
        + content
    )


def wifi_direct_device_info_att(
    dev_addr,
    methods,
    dev_cat,
    dev_oui,
    dev_subcat,
    num_sec_dev_types,
    dev_name_type,
    dev_name,
):
    # MAC address.
    # can be the same as source addr or different (Wifi Direct gives
    # option for one device to open number of connections, each connection
    # will have to get unique MAC addr)
    p2p_device_addr = unhexlify(mac_addr_to_hex(dev_addr))

    # 16 bits binary string.
    # from right to left: Flash, Ethernet, Label, Display, External NFC, Integrated NFC, NFC Interface,
    # PushButton, Keypad
    config_methods = binary_str_to_bytes(methods)

    # 2 bytes hex string
    primary_device_type_category = unhexlify(dev_cat)

    # 4 bytes hex string
    primary_device_type_oui = unhexlify(dev_oui)

    # 2 bytes hex string
    primary_device_type_subcategory = unhexlify(dev_subcat)

    # One byte hex string
    number_of_secondary_device_types = unhexlify(num_sec_dev_types)

    # 2 bytes hex string
    device_name_att_type = unhexlify(dev_name_type)

    # string
    device_name = bytes(dev_name, encoding="utf8")

    device_name_len = (len(device_name)).to_bytes(2, byteorder="big")

    content = p2p_device_addr + config_methods + primary_device_type_category
    content += primary_device_type_oui + primary_device_type_subcategory
    content += number_of_secondary_device_types + device_name_att_type
    content += device_name_len + device_name

    return (
        DIRECT_ATT["DEVICE_INFO"]
        + len(content).to_bytes(2, byteorder="little")
        + content
    )


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
def wifi_display_ie(flags, port, throughput):
    header = wifi_display_ie_header()

    content = wifi_display_device_info_se(flags, port, throughput)

    return header + content


def wifi_wps_ie_header():
    return WPS_OUI + OUI_TYPE["WPS"]


def wps_version_att():
    # Deprecated. Always set to 0x10 for backwards compatibility
    return WPS_ATT["VERSION"] + unhexlify("000110")


def wps_req_type_att():
    # 1 bytes hex string
    # The Request Type component specifies the mode in which the device will operate in for 
    # this setup exchange.   
    # for now fixed on enrollee, open 802.1x
    return WPS_ATT["REQUEST_TYPE"] + unhexlify("000101")


def wps_config_methods_att(config_methods):
    # 16 bits binary string 
    # The Configuration Methods Data component lists the configuration methods the 
    # Enrollee or Registrar supports.
    # from right to left - USB, Ethernet, Label, Display, External NFC, Internal NFC
    # NFC Interface, Push Button, Keypad, Virtual Push Button, Physical Push Button
    # null, null, Virtual Display, Physical Display, null
    bin_config_methods = binary_str_to_bytes(config_methods)
    return (
        WPS_ATT["CONFIG_METHODS"]
        + len(bin_config_methods).to_bytes(2, byteorder="big")
        + bin_config_methods
    )


def wps_uuid_e_att(uuid_e):
    # 16 bytes hex string
    # The universally unique identifier (UUID) element is a unique GUID generated by the
    # Enrollee. It uniquely identifies an operational device and should survive reboots and
    # resets.
    bin_uuid_e = unhexlify(uuid_e)
    return (
        WPS_ATT["UUID_E"] + len(bin_uuid_e).to_bytes(2, byteorder="big") + bin_uuid_e
    )


def wps_dev_type_att(dev_type):
    bin_dev_type = unhexlify(dev_type)
    return (
        WPS_ATT["DEV_TYPE"]
        + len(bin_dev_type).to_bytes(2, byteorder="big")
        + bin_dev_type
    )


def wps_rf_bands_att():
    # 2.4 or 5 GHz
    return WPS_ATT["RF_BANDS"] + unhexlify("000103")


def wps_assoc_state_att():
    # not associated
    return WPS_ATT["ASSOC_STATE"] + unhexlify("00020000")


def wps_conf_error_att():
    # no error
     return WPS_ATT["CONF_ERROR"] + unhexlify("00020000")


def wps_pass_id_att(pass_id):
    bin_pass_id = unhexlify(pass_id)
    return (
        WPS_ATT["PASS_ID"]
        + len(bin_pass_id).to_bytes(2, byteorder="big")
        + bin_pass_id
    )


def wps_manufacturer_att(manufacturer):   
    bin_manufacturer = bytes(manufacturer, encoding="utf8")
    return (
        WPS_ATT["MANUFACTURER"]
        + len(bin_manufacturer).to_bytes(2, byteorder="big")
        + bin_manufacturer
    )


def wps_model_name_att(model_name):
    bin_model_name = bytes(model_name, encoding="utf8")
    return (
        WPS_ATT["MODEL_NAME"]
        + len(bin_model_name).to_bytes(2, byteorder="big")
        + bin_model_name
    )


def wps_model_num_att(model_num):       
    bin_model_num = bytes(model_num, encoding="utf8")
    return (
        WPS_ATT["MODEL_NUM"]
        + len(bin_model_num).to_bytes(2, byteorder="big")
        + bin_model_num
    )


def wps_dev_name_att(dev_name):    
    bin_dev_name = bytes(dev_name, encoding="utf8")
    return (
        WPS_ATT["DEV_NAME"]
        + len(bin_dev_name).to_bytes(2, byteorder="big")
        + bin_dev_name
    )


def wps_ver_2_att():
    # version 2 request to enroll
    return WPS_ATT["VERSION_2"] + unhexlify("000900372a000120030101")


def create_probe_req(src_mac, ssid, config_methods, pass_id):
    # basic headers
    frame = RadioTap()
    frame /= Dot11(addr1=BROADCAST_MAC, addr2=src_mac, addr3=BROADCAST_MAC)
    frame /= Dot11ProbeReq()
    frame /= Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame /= Dot11EltRates(rates=[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C])

    wps_ie_header = wifi_wps_ie_header()
    wps_ie_content = (
        wps_version_att() +
        wps_req_type_att() +
        wps_config_methods_att(config_methods) +
        wps_uuid_e_att("12d78e1bef9359df8437b8dec4e0c31e") +
        wps_dev_type_att("000a0050f2040005") +
        wps_rf_bands_att() + 
        wps_assoc_state_att() +
        wps_conf_error_att() +
        wps_pass_id_att(pass_id) +
        wps_manufacturer_att("Technion") +
        wps_model_name_att("CS") +
        wps_model_num_att("2022") +
        wps_dev_name_att("Fuzzer")+
        wps_ver_2_att()
    )
    wps_ie = wps_ie_header + wps_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(wps_ie), len=len(wps_ie))

    display_ie = wifi_display_ie("0000000100010000", 7236, 50)
    frame /= Dot11Elt(ID=221, info=RawVal(display_ie), len=len(display_ie))

    direct_ie_header = wifi_direct_ie_header()
    direct_ie_content = (
        wifi_direct_capabilities_att("00100101", "00000000")
        + wifi_direct_listen_channel_att()
    )
    direct_ie = direct_ie_header + direct_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(direct_ie), len=len(direct_ie))

    return frame

def create_prov_disc_req(src_mac, dst_mac):
    # basic headers
    frame = RadioTap()
    frame /= Dot11(subtype=13, addr1=dst_mac, addr2=src_mac, addr3=dst_mac)

    # fixed parameters
    frame /= Raw(unhexlify("0409506f9a090701"))

    direct_ie_header = wifi_direct_ie_header()
    direct_ie_content = wifi_direct_capabilities_att(
        "00100101", "00000000"
    ) + wifi_direct_device_info_att(
        src_mac, "0000000110001000", "000a", "0050f204", "0005", "00", "1011", "Fuzzer"
    )
    direct_ie = direct_ie_header + direct_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(direct_ie), len=len(direct_ie))

    wps_ie_header = wifi_wps_ie_header()
    # For now fixed on PushButton
    wps_ie_content = wps_config_methods_att("0000000010000000")
    wps_ie = wps_ie_header + wps_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(wps_ie), len=len(wps_ie))

    display_ie = wifi_display_ie("0000000100010000", 7236, 50)
    frame /= Dot11Elt(ID=221, info=RawVal(display_ie), len=len(display_ie))

    return frame
        

def create_auth_req(src_mac, dst_mac):
    frame = RadioTap() 
    frame /= Dot11(addr1=dst_mac, addr2=src_mac, addr3=dst_mac)
    frame /= Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
    return frame


def create_asso_req(src_mac, dst_mac, ssid):
    frame = RadioTap()
    frame /= Dot11(addr1=dst_mac, addr2=src_mac, addr3=dst_mac)
    frame /= Dot11AssoReq(cap=0x1100, listen_interval=0x00A)
    frame /= Dot11Elt(ID=0, info=ssid)
    frame /= Dot11EltRates(rates=[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C])
    frame /= Dot11Elt(ID=36, info=RawVal(unhexlify("010d")), len=2)
    frame /= Dot11EltRSN()

    wps_ie_header = wifi_wps_ie_header()
    wps_ie_content = (
        wps_version_att() +
        wps_req_type_att() +
        wps_ver_2_att()
    )
    wps_ie = wps_ie_header + wps_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(wps_ie), len=len(wps_ie))

    display_ie = wifi_display_ie("0000000100010000", 7236, 50)
    frame /= Dot11Elt(ID=221, info=RawVal(display_ie), len=len(display_ie))

    direct_ie_header = wifi_direct_ie_header()
    direct_ie_content = wifi_direct_capabilities_att(
        "00100111", "00000000"
    ) + wifi_direct_device_info_att(
        src_mac, "0000000110001000", "000a", "0050f204", "0005", "00", "1011", "Fuzzer"
    )
    direct_ie = direct_ie_header + direct_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(direct_ie), len=len(direct_ie))

    return frame


def create_probe_res(dst_mac, src_mac="00:01:02:03:04:05", ssid="DIRECT-TEST"):
    # basic headers
    frame = RadioTap()
    frame /= Dot11(addr1=dest_mac, addr2=source_mac, addr3=source_mac)
    frame /= Dot11ProbeResp()
    frame /= Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame /= Dot11EltRates(rates=[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C])

    display_ie = wifi_display_ie()
    frame /= Dot11Elt(ID=221, info=RawVal(display_ie), len=len(display_ie))

    direct_ie_header = wifi_direct_ie_header()
    direct_ie_content = wifi_direct_capabilities_att(
        "00100101", "00101011"
    ) + wifi_direct_device_info_att(
        src_mac, "0000000110001000", "000a", "0050f204", "0005", "00", "1011", ssid
    )
    direct_ie = direct_ie_header + direct_ie_content
    frame /= Dot11Elt(ID=221, info=RawVal(direct_ie), len=len(direct_ie))

    return frame


def get_device_p2p_addr(packet):
		ie = packet[Dot11EltVendorSpecific]
		while isinstance(ie, Dot11EltVendorSpecific):
				if ie.info[:3] == WIFI_OUI and ie.info[3] == 9: 
						# assuming the direct ie contains only capabilities and device info attributes (in this order)
						return ie.info[12:18]
				ie = ie.payload

		return None
