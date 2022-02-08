# Here is a sample cookie:
# 5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3
# What is your cookie?

from pwn import *  # Import lib to use the APIs, just like any Python lib
# Suppress non-error messages, i.e. less verbose runtime output
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)


# sample_cookie_prompt = "Here is a sample cookie: "
# sample_cookie = oracle.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
# sample_cookie = sample_cookie[len(sample_cookie_prompt):]
# print("\nOracle's sample cookie:")
# print(sample_cookie)

for xor_val in range(0x00, 0xFF):
    oracle = remote('192.168.2.83', 26151)

    # cookie length is 192 => 12 blocks
    cookie = "5468697320697320616e204956343536069242ad5ac3e289582b09ff2d30032b0e72a2004dc6d37181448f0327a2a3f3fe3280b99951c832ca8d08940716d226af1a2edddadfdbe92a5933f4d869c714e53842a369eb89a44ae1159b3b73f3d3"
    replaced = hex(int(cookie[-12:-10], 16) ^ xor_val)[2:]
    # print(len(replaced))
    # print(replaced)
    # cookie = cookie[:-10] + replaced + cookie[-8:]
    cookie = cookie[:-12] + replaced + cookie[-10:]
    replaced = hex(int(cookie[-10:-8], 16) ^ 0x00 ^ 0x02)[2:]
    # print(len(replaced))
    # print(replaced)
    # cookie = cookie[:-10] + replaced + cookie[-8:]
    cookie = cookie[:-10] + replaced + cookie[-8:]

    # print(cookie)
    # print(len(cookie))
    oracle.recvline_contains("What is your cookie?", keepends=False, timeout=5)
    oracle.sendline(cookie)
    response = oracle.recvall()
    if "invalid" not in response.decode():
        print(response)
        print(hex(xor_val))

