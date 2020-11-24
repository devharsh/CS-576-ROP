import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/home/dtrived5/victim.sock")
s.send(b'Hello\n4\n')
data = s.recv(1024)
s.close()
print('Received ' + repr(data))
