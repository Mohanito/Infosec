#!/usr/bin/python
encrypted_flag = "c16768deb38a7e0bf768066b91ebb26c4a5a153dce13c662dadfa1625ee78d8d"
message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
encrypted = "97343f8de6d22d59a63f5f3ec0bde33a1f0f47659f449231888bf4330fb3d9dc"
# convert message to hex
message_hex = ""
for i in range(len(message)):
    byte = hex(ord(message[i]))[2:]
    if len(byte) == 1:
        byte = '0' + byte
    message_hex += byte

# XOR message and encrypted to find key
key = ""
for i in range(0, len(encrypted), 2):
    encrypted_byte = int(encrypted[i: i + 2], 16)
    message_byte = int(message_hex[i : i + 2], 16)
    byte = hex(encrypted_byte ^ message_byte)[2:]
    if len(byte) == 1:
        byte = '0' + byte
    key += byte
print("Key is: " + key)

flag_hex = int(encrypted_flag, 16) ^ int(key, 16)
flag_hex = hex(flag_hex)[2:]
flag = ""
# convert flag back to string
for i in range(0, len(flag_hex), 2):
    flag += chr(int(flag_hex[i: i + 2], 16))
print(flag)