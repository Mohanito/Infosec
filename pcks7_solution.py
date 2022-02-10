# Here is a sample cookie:
# 5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3
# What is your cookie?

from dataclasses import replace
from pwn import *  # Import lib to use the APIs, just like any Python lib
import re
# Suppress non-error messages, i.e. less verbose runtime output
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)

# Globals
cookie = "5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3"
plaintext = ""
prev_xor_vals = []
IV="This is an IV456"


def attack_block(cipher, pre, post):
    # cipher contains 2 blocks, cipher[0:32] and cipher[32:]
    for pos in range(16):   # 16 bytes per block
        for xor_val in range(256):    # 0x00 to 0xFF
            # unused for now
            # xor_val_hex = hex(xor_val).split("0x")[1]

            oracle = remote('192.168.2.83', 26151)
            # get rid of welcome messages
            oracle.recvline_contains("What is your cookie?", keepends = False, timeout = 5)

            # segment that should not be modified
            message = cipher[0: 32 - 2 * (pos + 1)]

            # xor current byte with current xor_val
            replaced_byte = hex(
                int(cipher[32 - 2 * (pos + 1): 32 - 2 * pos], 16) ^ xor_val)[2:]
            while len(replaced_byte) < 2:
                replaced_byte = "0" + replaced_byte
            message += replaced_byte

            # for the remaining first half, XOR it with (previous xor_vals XOR current padding)
            for prev_pos in range(pos - 1, -1, -1):
                replaced_byte = hex(
                    int(cipher[32 - 2 * (prev_pos + 1): 32 - 2 * prev_pos], 16)
                    ^ prev_xor_vals[prev_pos]
                    ^ (pos + 1))[2:]
                while len(replaced_byte) < 2:
                    replaced_byte = "0" + replaced_byte
                message += replaced_byte
            
            print("first half C(n-1) is: " + message)

            # append the second half
            message += cipher[32:]

            # prepend / append message with the other 192 - 64 chars
            # sending partial causes server failure in json.parse()
            # message = pre + message + post

            # print(len(message)) # 192
            oracle.sendline(message)
            response = oracle.recvall()
            # if pos == 1:
            # print(response)

            if "padding" not in response.decode():
                print(response)
                print(message)
                if pos + 1 == len(prev_xor_vals):
                    prev_xor_vals[pos] = xor_val
                else:
                    prev_xor_vals.append(xor_val)
                print(prev_xor_vals)
                # plaintext = hex((pos + 1) ^ xor_val).split("0x")[1] + plaintext
                # print(plaintext)

            # print(message)
            # result = "00" * (16 - 1 - pos) + ("0" if len(xor_val) %
            #                                   2 != 0 else "") + xor_val + c_n

if __name__ == "__main__":
    # try decrypting the first block
    IV_HEX = ""
    for ch in IV:
        ch_hex = hex(ord(ch))[2:]
        while len(ch_hex) < 2:
            ch_hex = "0" + ch_hex
        IV_HEX += ch_hex
    print(IV_HEX + cookie[0:32])
    print(len(IV_HEX + cookie[0:32]))
    attack_block(IV_HEX + cookie[0:32], "", "")

    # part 1: decryption attack
    for blockIndex in range(6):
        if blockIndex == 5:
            print("first half now becomes IV. fix later")
            break
        # 2-block segments = 64 chars = 32 bytes
        c = cookie[len(cookie) - 64 * (blockIndex + 1): len(cookie) - 64 * blockIndex]
        pre = cookie[0: len(cookie) - 64 * (blockIndex + 1)]
        post = cookie[len(cookie) - 64 * blockIndex :]
        attack_block(c, pre, post)

    # part 2: encryption attack
    # first get dec(c_n)
    # 1. C_desired[n-1] = Dec[C[n]] ^ P_desired[n]
    # 2. Compute Dec[C[n-1]] using C_desired[n-1]
    # 3. repeat 5? times





# unused for now

# for xor_val in range(0x00, 0xFF):
#     oracle = remote('192.168.2.83', 26151)

#     # cookie length is 192 => 12 blocks
#     replaced = hex(int(cookie[-12:-10], 16) ^ xor_val)[2:]
#     # print(len(replaced))
#     # print(replaced)
#     # cookie = cookie[:-10] + replaced + cookie[-8:]
#     cookie = cookie[:-12] + replaced + cookie[-10:]
#     replaced = hex(int(cookie[-10:-8], 16) ^ 0x00 ^ 0x02)[2:]
#     # print(len(replaced))
#     # print(replaced)
#     # cookie = cookie[:-10] + replaced + cookie[-8:]
#     cookie = cookie[:-10] + replaced + cookie[-8:]

#     # print(cookie)
#     # print(len(cookie))
#     oracle.recvline_contains("What is your cookie?", keepends=False, timeout=5)
#     oracle.sendline(cookie)
#     response = oracle.recvall()
#     if "invalid" not in response.decode():
#         print(response)
#         print(hex(xor_val))

# used to xor original c_n
# xor_mask = "00000000000000000000000000000000"
#====

# def split_len(seq, length):
#     return [seq[i : i + length] for i in range(0, len(seq), length)]


# """ Create custom block for the byte we search"""


# def block_search_byte(size_block, i, pos, l):
#     hex_char = hex(pos).split("0x")[1]
#     return (
#         "00" * (size_block - (i + 1))
#         + ("0" if len(hex_char) % 2 != 0 else "")
#         + hex_char
#         + "".join(l)
#     )


# """ Create custom block for the padding"""


# def block_padding(size_block, i):
#     l = []
#     for t in range(0, i + 1):
#         l.append(
#             ("0" if len(hex(i + 1).split("0x")[1]) % 2 != 0 else "")
#             + (hex(i + 1).split("0x")[1])
#         )
#     return "00" * (size_block - (i + 1)) + "".join(l)


# def hex_xor(s1, s2):
#     b = bytearray()
#     for c1, c2 in zip(bytes.fromhex(s1), cycle(bytes.fromhex(s2))):
#         b.append(c1 ^ c2)
#     return b.hex()


# def run(cipher, size_block, host, url, cookie, method, post, error):
#     cipher = cipher.upper()
#     found = False
#     valide_value = []
#     result = []
#     cipher_block = split_len(cookie, 32)

#     # for each cipher_block
#     for block in reversed(range(1, len(cipher_block))):
#         # for each byte of the block
#         for i in range(0, size_block):
#             # test each byte max 255
#             for ct_pos in range(0, 256):
#                 oracle = remote('192.168.2.83', 26151)
#                 oracle.recvline_contains("What is your cookie?", keepends = False, timeout = 5)
#                 if ct_pos != i + 1 or (
#                     len(valide_value) > 0 and int(valide_value[-1], 16) == ct_pos
#                 ):

#                     bk = block_search_byte(size_block, i, ct_pos, valide_value)
#                     bp = cipher_block[block - 1]
#                     bc = block_padding(size_block, i)

#                     tmp = hex_xor(bk, bp)
#                     cb = hex_xor(tmp, bc).upper()

#                     up_cipher = cb + cipher_block[block]
                   
#                     oracle.sendline(message)
#                     response = oracle.recvall()

#                     if "username" in response.decode():
#                         exe = re.findall("..", cb)
#                         discover = ("").join(exe[size_block - i : size_block])
#                         current = ("").join(exe[size_block - i - 1 : size_block - i])
#                         find_me = ("").join(exe[: -i - 1])

#                         sys.stdout.write(
#                             "\r[+] Test [Byte %03i/256 - Block %d ]: \033[31m%s\033[33m%s\033[36m%s\033[0m"
#                             % (ct_pos, block, find_me, current, discover)
#                         )
#                         sys.stdout.flush()

#                     if test_validity(response, error):

#                         found = True
#                         connection.close()

#                         # data analyse and insert in right order
#                         value = re.findall("..", bk)
#                         valide_value.insert(0, value[size_block - (i + 1)])

#                         print("")
#                         print("[+] Block M_Byte : %s" % bk)
#                         print("[+] Block C_{i-1}: %s" % bp)
#                         print("[+] Block Padding: %s" % bc)
#                         print("")

#                         bytes_found = "".join(valide_value)
#                         if (
#                             i == 0
#                             and int(bytes_found, 16) > size_block
#                             and block == len(cipher_block) - 1
#                         ):
#                             print(
#                                 "[-] Error decryption failed the padding is > "
#                                 + str(size_block)
#                             )
#                             sys.exit()

#                         print(
#                             "\033[36m" + "\033[1m" + "[+]" + "\033[0m" + " Found",
#                             i + 1,
#                             "bytes :",
#                             bytes_found,
#                         )
#                         print("")

#                         break
#             if found == False:
#                 # lets say padding is 01 for the last byte of the last block (the padding block)
#                 if len(cipher_block) - 1 == block and i == 0:
#                     value = re.findall("..", bk)
#                     valide_value.insert(0, "01")
#                     if args.verbose == True:
#                         print("")
#                         print(
#                             "[-] No padding found, but maybe the padding is length 01 :)"
#                         )
#                         print("[+] Block M_Byte : %s" % bk)
#                         print("[+] Block C_{i-1}: %s" % bp)
#                         print("[+] Block Padding: %s" % bc)
#                         print("")
#                         bytes_found = "".join(valide_value)
#                 else:
#                     print("\n[-] Error decryption failed")
#                     result.insert(0, "".join(valide_value))
#                     hex_r = "".join(result)
#                     print("[+] Partial Decrypted value (HEX):", hex_r.upper())
#                     padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
#                     print(
#                         "[+] Partial Decrypted value (ASCII):",
#                         bytes.fromhex(hex_r[0 : -(padding * 2)]).decode(),
#                     )
#                     sys.exit()
#             found = False

#         result.insert(0, "".join(valide_value))
#         valide_value = []

#     print("")
#     hex_r = "".join(result)
#     print("[+] Decrypted value (HEX):", hex_r.upper())
#     padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
#     print(
#         "[+] Decrypted value (ASCII):",
#         bytes.fromhex(hex_r[0 : -(padding * 2)]).decode(),
#     )