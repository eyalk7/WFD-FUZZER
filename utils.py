from random import choice, randrange
from string import ascii_letters


def binary_str_to_bytes(s):
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def mac_addr_to_hex(addr):
    return "".join([c if (i + 1) % 3 else "" for i, c in enumerate(addr)])

def create_seq_num(seq):
    return seq << 4

def create_string_ascii():
    return bytearray(''.join(choice(ascii_letters) for _ in range(randrange(1,256))), 'utf-8')

def create_string_inject_pattern(pattern):
    """
    Creates a random ascii string with random length, and injects the given 
    bytes pattern to it in a random place and random number of times.
    """
    string = create_string_ascii()
    start = randrange(len(string)-len(pattern))
    times = randrange((len(string)-start)/len(pattern))
    string[start:start+times*len(pattern)] = pattern * times
    return string


def create_string_x86opcode():    
    return create_string_inject_pattern(choice([b'\x33',b'\x90']))


def create_string_specialchar():
    return create_string_inject_pattern(choice([b'\x00',b'\xfe',b'\xff',b'\xef',b'\xbb',b'\xbf',b'\x10\xff\xff']))


def create_string_format():    
    return create_string_inject_pattern(b'\x25'+choice([b'\x70',b'\x64',b'\x63',b'\x75',b'\x78',b'\x73',b'\x6e']))

def mac_iterator(starting_value=1, max_iterations=64):
    """
    create an iterator of mac addresses. 
    starting value is a number represnting a mac address. 1 is 00:00:00:00:00:01 and so on.

    we create an iterator and not a list in case we want to run over a lot of macs
    """
    for i in range(starting_value, starting_value + max_iterations):
        mac_int = i
        mac_hex = "{:012x}".format(mac_int)
        mac_str = ":".join(mac_hex[j:j+2] for j in range(0, len(mac_hex), 2))
        yield mac_str