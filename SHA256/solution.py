# Here is your cookie as plaintext:
# username=nekomusume&groups=students,users,
# And here it is as hex:
# 757365726e616d653d6e656b6f6d7573756d652667726f7570733d73747564656e74732c75736572732c
# SECRET_KEY is a 16-byte key that is unknown to you
# The signature is computed as SHA256(SECRET_KEY || message)
# The signature of your cookie is:
# daa9ddb8ac90b99965b4e2bfaae1ea32ba695f63f031b9f8e551d57572e395fd

import struct

# ------------------------------------------------
# ------ Pure-Python3 SHA256 Implementation ------
# ------------------------------------------------

# SHA256 constants
k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

# Similar to right-shift but bits that are shifted out from the right are
# shifted back into the left


def right_rotate(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

# Addition modulo 2^32


def add32(*args):
    return sum(args) % (2**32)


def add_padding(msg):
    # Uses standard SHA256 padding scheme, assuming initial message consists of bytes:
    # Append a single 1-bit, then extend with 0s until length is 64 bits less than
    # a multiple of 512 bits, then append the 64-bit integer form of the original
    # message's length
    len_orig = 8 * len(msg)
    msg = msg + b"\x80"

    while (len(msg) + 8) % 64 != 0:
        msg = msg + b"\x00"

    # Add original message length to end as an 8-byte big-endian integer
    msg = msg + struct.pack(">Q", len_orig)

    return msg

# Main SHA256 implementation


def sha256(data_str):
    msg = data_str

    # if isinstance(msg, str):
    #     msg = msg.encode() # Convert string to bytearray

    # data_padded = add_padding(msg)

    # assert len(data_padded) % 64 == 0

    # we get this from the signature provided
    # daa9ddb8 ac90b999 65b4e2bf aae1ea32 ba695f63 f031b9f8 e551d575 72e395fd
    h0 = 0xdaa9ddb8
    h1 = 0xac90b999
    h2 = 0x65b4e2bf
    h3 = 0xaae1ea32
    h4 = 0xba695f63
    h5 = 0xf031b9f8
    h6 = 0xe551d575
    h7 = 0x72e395fd

    for i in range(0, len(msg), 64):
        data_chunk = msg[i:i+64]

        w = [0] * 64  # Message schedule array

        # Chunk forms the start of the message schedule array
        for i in range(0, 16):
            w[i] = struct.unpack(">I", data_chunk[(4*i):(4*i+4)])[0]

        # Extend to form the rest of the message schedule array
        for i in range(16, 64):
            s0 = right_rotate(
                w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(
                w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = add32(w[i - 16], s0, w[i - 7], s1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # The compression function
        for i in range(0, 64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = add32(h, S1, ch, k[i], w[i])
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = add32(S0, maj)

            h = g
            g = f
            f = e
            e = add32(d, temp1)
            d = c
            c = b
            b = a
            a = add32(temp1, temp2)

        h0 = add32(h0, a)
        h1 = add32(h1, b)
        h2 = add32(h2, c)
        h3 = add32(h3, d)
        h4 = add32(h4, e)
        h5 = add32(h5, f)
        h6 = add32(h6, g)
        h7 = add32(h7, h)

    return struct.pack(">IIIIIIII", h0, h1, h2, h3, h4, h5, h6, h7).hex()


# Here's the main function:

cookie = "1234567812345678" + "username=nekomusume&groups=students,users,"
new_cookie = "admins"
combined_msg = add_padding(add_padding(cookie.encode()) + new_cookie.encode())
print(combined_msg.hex())
# 31323334353637383132333435363738757365726e616d653d6e656b6f6d7573756d652667726f7570733d73747564656e74732c75736572732c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d061646d696e7380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000430

# Please provide your cookie as hex:
# 757365726e616d653d6e656b6f6d7573756d652667726f7570733d73747564656e74732c75736572732c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d061646d696e73

print(sha256(combined_msg[-64:]))
# Please provide the signature SHA256(SECRET_KEY || message) of the cookie:
# 65a87a123fd70070374589b733ada274054eeb21b774f9214f09feff4c960407

# flag: 6eb8e6139264f79e3e0a6697d0060b5a
