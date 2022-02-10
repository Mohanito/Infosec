# Here is a sample cookie:
# 5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3
# What is your cookie?

from dataclasses import replace
from pwn import *  # Import lib to use the APIs, just like any Python lib
# Suppress non-error messages, i.e. less verbose runtime output
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)

# Globals
cookie = "5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3"
plaintext = ""
prev_xor_vals = []

def attack_block(cipher, pre, post):
    # cipher contains 2 blocks, cipher[0:32] and cipher[32:]
    for pos in range(16):   # 16 bytes per block
        for xor_val in range(256):    # 0x00 to 0xFF
            # unused for now
            # xor_val_hex = hex(xor_val).split("0x")[1]

            oracle = remote('192.168.2.83', 26151)
            # get rid of welcome messages
            oracle.recvline_contains("What is your cookie?", keepends=False, timeout=5)


            # segment that should not be modified
            message = cipher[0: 32 - 2 * (pos + 1)]

            # xor cipher[0:32] with current xor_val
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
                    ^ pos)[2:]
                while len(replaced_byte) < 2:
                    replaced_byte = "0" + replaced_byte
                message += replaced_byte
            
            print("first half C(n-1) is: " + message)

            # append the second half
            message += cipher[32:]

            # prepend / append message with the other 192 - 64 chars
            # sending partial causes server failure in json.parse()
            message = pre + message + post

            # print(len(message)) # 192
            oracle.sendline(message)
            response = oracle.recvall()
            if pos == 2:
                print(response)

            if "username" in response.decode():
                print(response)
                print(message)
                prev_xor_vals.append(xor_val)
                print(prev_xor_vals)
                # plaintext = hex((pos + 1) ^ xor_val).split("0x")[1] + plaintext
                # print(plaintext)

            # print(message)
            # result = "00" * (16 - 1 - pos) + ("0" if len(xor_val) %
            #                                   2 != 0 else "") + xor_val + c_n

if __name__ == "__main__":

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