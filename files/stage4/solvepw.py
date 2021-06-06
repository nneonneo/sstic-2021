import numpy as np

def round(r0, r1, r2, r3):
    r0 += r1
    r3 ^= r0

    r2 += r3
    r1 ^= r2
    r1 = (r1 << 12) | (r1 >> 20)

    r0 += r1
    r3 ^= r0
    r3 = (r3 << 8) | (r3 >> 24)

    r2 += r3
    r1 ^= r2
    r1 = (r1 << 7) | (r1 >> 25)
    return r0, r1, r2, r3

def unround(r0, r1, r2, r3):
    r1 = (r1 >> 7) | (r1 << 25)
    r1 ^= r2
    r2 -= r3

    r3 = (r3 >> 8) | (r3 << 24)
    r3 ^= r0
    r0 -= r1

    r1 = (r1 >> 12) | (r1 << 20)
    r1 ^= r2
    r2 -= r3

    r3 = (r3 >> 16) | (r3 << 16)
    r3 ^= r0
    r0 -= r1

    return r0, r1, r2, r3

def munge(input):
    r0, r1, r2, r3 = [c.copy() for c in np.frombuffer(input, dtype='<u4').reshape((4, 4))]
    for i in range(20):
        if i % 2 == 0:
            r0, r1, r2, r3 = round(r0, r1, r2, r3)
        else:
            r1 = np.roll(r1, -1)
            r2 = np.roll(r2, -2)
            r3 = np.roll(r3, -3)
            r0, r1, r2, r3 = round(r0, r1, r2, r3)
            r3 = np.roll(r3, -1)
            r2 = np.roll(r2, -2)
            r1 = np.roll(r1, -3)

    r0[0] += 0x2000
    r1[0] += 0x2010
    r2[0] += 0x2020
    r3[0] += 0x2030
    buf = bytearray(bytes(r0) + bytes(r1) + bytes(r2) + bytes(r3))
    xor = open('0x100_data.bin', 'rb').read()
    for i in range(64):
        buf[i] ^= xor[i]
    return buf

def unmunge(input):
    buf = bytearray(input)
    xor = open('0x100_data.bin', 'rb').read()
    for i in range(64):
        buf[i] ^= xor[i]
    r0, r1, r2, r3 = [c.copy() for c in np.frombuffer(buf, dtype='<u4').reshape((4, 4))]
    r0[0] -= 0x2000
    r1[0] -= 0x2010
    r2[0] -= 0x2020
    r3[0] -= 0x2030
    for i in reversed(range(20)):
        if i % 2 == 0:
            r0, r1, r2, r3 = unround(r0, r1, r2, r3)
        else:
            r3 = np.roll(r3, 1)
            r2 = np.roll(r2, 2)
            r1 = np.roll(r1, 3)
            r0, r1, r2, r3 = unround(r0, r1, r2, r3)
            r1 = np.roll(r1, 1)
            r2 = np.roll(r2, 2)
            r3 = np.roll(r3, 3)

    return bytes(r0) + bytes(r1) + bytes(r2) + bytes(r3)

print(munge(b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa').hex())
print(unmunge(bytes.fromhex('f235422649261a9207aa8139f3b6fc9f85d5084c8b0824e80514e4b2223d802a6a5728abda4dcaf51db348c575a7b6a14847ef8a4fc4e13ca96356c2f30a1def')))
output = unmunge(b'\xff' * 48 + b"EXECUTE FILE OK!")
open('pw.bin', 'wb').write(output + bytes.fromhex('0e 03 05 0a 08 04 09 0b 00 0c 0d 07 0f 02 06 01'))

