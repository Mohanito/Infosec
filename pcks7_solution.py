from pwn import *  # Import lib to use the APIs, just like any Python lib
# Suppress non-error messages, i.e. less verbose runtime output
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)

# Globals
cookie = "5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3"
plaintext = ""
prev_xor_vals = []
correct_guesses = []
IV="This is an IV456"

'''
    attack_block: decrypts one block of cookie into plaintext

    cipher: 2-block segment of the original cookie
    if 192 chars instead of 64 chars need to be sent,
    send pre + C' + post as message.
'''
def attack_block(cipher, pre, post):
    global plaintext    # removing this may cause "referenced before assignment error"

    # cipher contains 2 blocks, cipher[0:32] and cipher[32:]
    for pos in range(16):   # 16 bytes per block
        for xor_val in range(256):    # 0x00 to 0xFF

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
                    ^ correct_guesses[prev_pos]
                    ^ (pos + 1))[2:]
                while len(replaced_byte) < 2:
                    replaced_byte = "0" + replaced_byte
                message += replaced_byte
            
            # print("first half C(n-1) is: " + message)

            # append the second half
            message += cipher[32:]

            oracle.sendline(message)
            response = oracle.recvall()

            if "padding" not in response.decode():
                print(response)
                # if multiple xor_val's are valid, keep only the latest one
                if pos + 1 == len(prev_xor_vals):
                    prev_xor_vals[pos] = xor_val
                    correct_guesses[pos] = xor_val ^ (pos + 1)
                else:
                    prev_xor_vals.append(xor_val)
                    correct_guesses.append(xor_val ^ (pos + 1))
                print(prev_xor_vals)
                print(correct_guesses)
                plaintext = chr((pos + 1) ^ xor_val) + plaintext
        print("New iteration: current plaintext is:" + plaintext)
    return


if __name__ == "__main__":
    # result of the first block 0 - 64
    # {"username": "gu

    # result of 32 - 96:
    # est", "expires":
    # [58, 34, 115, 101, 114, 105, 112, 120, 101, 34, 32, 44, 34, 116, 115, 101, 1, 13, 34]

    # result of 64 - 128: (1 space char at the beginning)
    #  "2000-01-07", "
    # [34, 32, 44, 34, 55, 48, 45, 49, 48, 45, 48, 48, 48, 50, 34, 32]

    # result of 96 - 160:
    # is_admin": "fals
    # [115, 108, 97, 102, 34, 32, 58, 34, 110, 105, 109, 100, 97, 95, 115, 105]

    # last block reversed order
    # [13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 125, 34, 101]
    # obviously, plaintext is e"} and 13 paddings

    # plaintext is {"username": "guest", "expires": "2000-01-07", "is_admin": "false"} and 13 paddings

    IV_HEX = ""
    for ch in IV:
        ch_hex = hex(ord(ch))[2:]
        while len(ch_hex) < 2:
            ch_hex = "0" + ch_hex
        IV_HEX += ch_hex
    # IV_HEX seems to be identical to cookie[0:64]

    # part 1: decryption attack - for simplicity, run this 5 times
    # 0 - 64, 32 - 96, 64 - 128, 96 - 160, 128 - 192
    # attack_block(cookie[0:64], "", "")
    # attack_block(cookie[32:96], "", "")
    # attack_block(cookie[64:128], "", "")
    attack_block(cookie[96:160], "", "")
    # attack_block(cookie[128:192], "", "")
    
    print("Decryption done. Plaintext is: " + plaintext)

    # # for loop method unused for now, program may not exit normally
    # for blockIndex in range(6):
    #     # if blockIndex == 5:
    #     #     # first half now becomes IV
    #     #     attack_block(IV_HEX + cookie[0:32], "", "")
    #     #     break
    #     # 2-block segments = 64 chars = 32 bytes
    #     c = cookie[len(cookie) - 64 * (blockIndex + 1): len(cookie) - 64 * blockIndex]
    #     # pre = cookie[0: len(cookie) - 64 * (blockIndex + 1)]
    #     # post = cookie[len(cookie) - 64 * blockIndex :]
    #     attack_block(c, "", "")
    

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
