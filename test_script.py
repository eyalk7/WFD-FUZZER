from fuzzer import *
PHONE_MAC = "00:00:00:00:00:01"

response = probe_req_loop(PHONE_MAC)
auth_req = create_auth_req(PHONE_MAC, response.addr2)
auth_ans = None
while not auth_ans:
	ans, unans = srp(auth_req, iface=IFACE, inter=0.1, timeout=0.1)
	if ans:
		auth_ans = ans #it is a tuple of pkt sent and response