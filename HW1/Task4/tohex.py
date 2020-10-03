import binascii
filename = 'hello.sc'
with open(filename, 'rb') as f:
    content = f.read()
print(binascii.hexlify(content))
