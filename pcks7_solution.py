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
    return correct_guesses

'''
    generate_cipher: translates our plaintext to a 192-char message to send to server
    specifically, get C_desired_5, C_desired_4, C_desired_3, C_desired_2, C_desired_1
'''
def generate_cipher(dec_c_6, valid_plaintext_hex):
    # 1. C_desired[n-1] = Dec[C[n]] ^ P_desired[n]
    # 2. Compute Dec[C[n-1]] using C_desired[n-1]
    # 3. repeat

    # Step 1/5: get c_desired_5, compute dec_c_5
    p_desired_6 = valid_plaintext_hex[128:160]
    c_desired_5 = hex(dec_c_6 ^ int(p_desired_6, 16))[2:]
    if len(c_desired_5) % 2:
        c_desired_5 = "0" + c_desired_5
    # print("INITIAL TEST C5C6  " + c_desired_5 + cookie[160:192])    
    # c_desired_5 + c6 - passed because c_desired_5 is the original cookie segment
    # this is because the original text and our text has the same ending.

    # send c4 + c_desired_5 to the server. 
    # since c5 is changed, we need to guess the resulting p5 by modifying c4.
    # after getting p5, p5 xor c4 is dec(c5)
    original_c_4 = cookie[96:128]
    tmp_p5_array = [115, 108, 97, 102, 34, 32, 58, 34, 110, 105, 109, 100, 97, 95, 115, 105]
    # attack_block(original_c_4 + c_desired_5, "", "")
    print(tmp_p5_array)

    # reversely construct tmp p5
    tmp_p5 = ""
    for i in range(len(tmp_p5_array) - 1, -1, -1):
        p5_char = hex(tmp_p5_array[i])[2:]
        while len(p5_char) < 2:
            p5_char = "0" + p5_char
        tmp_p5 += p5_char
    print("tmp p5 in hex is: " + tmp_p5)    # aa999ff5da917d33d66f949f06dda912
    
    dec_c_5 = int(tmp_p5, 16) ^ int(original_c_4, 16)


    # Step 2/5: get c_desired_4, compute dec_c_4
    p_desired_5 = valid_plaintext_hex[96:128]
    c_desired_4 = hex(dec_c_5 ^ int(p_desired_5, 16))[2:]
    if len(c_desired_4) % 2:
        c_desired_4 = "0" + c_desired_4

    original_c_3 = cookie[64:96]
    tmp_p4_array = [181, 161, 183, 36, 121, 156, 104, 245, 143, 121, 30, 229, 7, 41, 135, 204]
    # attack_block(original_c_3 + c_desired_4, "", "")
    print(tmp_p4_array)
    
    # reversely construct tmp p4
    tmp_p4 = ""
    for i in range(len(tmp_p4_array) - 1, -1, -1):
        p4_char = hex(tmp_p4_array[i])[2:]
        while len(p4_char) < 2:
            p4_char = "0" + p4_char
        tmp_p4 += p4_char
    print("tmp p4 in hex is: " + tmp_p4)
    
    dec_c_4 = int(tmp_p4, 16) ^ int(original_c_3, 16)


    # Step 3/5: get c_desired_3, compute dec_c_3
    p_desired_4 = valid_plaintext_hex[64:96]
    c_desired_3 = hex(dec_c_4 ^ int(p_desired_4, 16))[2:]
    if len(c_desired_3) % 2:
        c_desired_3 = "0" + c_desired_3
    # print("cookie with c345 replaced:" + cookie[:64] + c_desired_3 + c_desired_4 + c_desired_5 + cookie[160:192])

    original_c_2 = cookie[32:64]
    tmp_p3_array = [122, 230, 186, 210, 37, 45, 98, 127, 130, 98, 171, 39, 67, 20, 63, 20]
    # attack_block(original_c_2 + c_desired_3, "", "")
    print(tmp_p3_array)
    
    # reversely construct tmp p3
    tmp_p3 = ""
    for i in range(len(tmp_p3_array) - 1, -1, -1):
        p3_char = hex(tmp_p3_array[i])[2:]
        while len(p3_char) < 2:
            p3_char = "0" + p3_char
        tmp_p3 += p3_char
    print("tmp p3 in hex is: " + tmp_p3)    # 143f144327ab62827f622d25d2bae67a
    
    dec_c_3 = int(tmp_p3, 16) ^ int(original_c_2, 16)



    # Step 4/5: get c_desired_2, compute dec_c_2
    p_desired_3 = valid_plaintext_hex[32:64]
    c_desired_2 = hex(dec_c_3 ^ int(p_desired_3, 16))[2:]
    if len(c_desired_2) % 2:
        c_desired_2 = "0" + c_desired_2
    print("cookie with c2345 replaced:" + cookie[:32] + c_desired_2 + c_desired_3 + c_desired_4 + c_desired_5 + cookie[160:192])

    original_c_1 = cookie[0:32]
    tmp_p2_array = [43, 167, 182, 141, 46, 213, 52, 167, 13, 68, 198, 65, 28, 176, 223, 212]
    # attack_block(original_c_1 + c_desired_2, "", "")
    print(tmp_p2_array)
    
    # reversely construct tmp p2
    tmp_p2 = ""
    for i in range(len(tmp_p2_array) - 1, -1, -1):
        p2_char = hex(tmp_p2_array[i])[2:]
        while len(p2_char) < 2:
            p2_char = "0" + p2_char
        tmp_p2 += p2_char
    print("tmp p2 in hex is: " + tmp_p2)
    
    dec_c_2 = int(tmp_p2, 16) ^ int(original_c_1, 16)

    # Step 5/5: get c_desired_1
    p_desired_2 = valid_plaintext_hex[0:32]
    c_desired_1 = hex(dec_c_2 ^ int(p_desired_2, 16))[2:]
    if len(c_desired_1) % 2:
        c_desired_1 = "0" + c_desired_1

    # now we have c_desired_1 + ... + c_desired_5 + original c6, send this to server
    attack_cookie = c_desired_1 + c_desired_2 + c_desired_3 + c_desired_4 + c_desired_5 + cookie[160:192]
    print("Attack cookie: ")
    print(attack_cookie)
    return attack_cookie

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
    # attack_block(cookie[0:64], "", "")
    # attack_block(cookie[32:96], "", "")
    # attack_block(cookie[64:128], "", "")
    # attack_block(cookie[96:160], "", "")
    # attack_block(cookie[128:192], "", "")
    
    # print("Decryption done. Plaintext is: " + plaintext)

    # part 2: encryption attack

    # adding 14 chars to the username avoids unprintable padding
    # {"username": "guest2", "expires": "2023-01-07", "is_admin": "true"}
    # we get this from an online string to hex converter
    valid_plaintext_hex = "7b22757365726e616d65223a2022677565737432222c202265787069726573223a2022323032332d30312d3037222c202269735f61646d696e223a202274727565227d"
    valid_plaintext_hex += "0d0d0d0d0d0d0d0d0d0d0d0d0d"
    # length is 160

    # first get dec(c_n) = original C(n - 1) XOR P(i)
    original_c_5 = cookie[128:160]
    # p6 is [13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 125, 34, 101] reversed
    p_6 = "65227d0d0d0d0d0d0d0d0d0d0d0d0d0d"
    dec_c_6 = int(original_c_5, 16) ^ int(p_6, 16)
    generate_cipher(dec_c_6, valid_plaintext_hex)




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

