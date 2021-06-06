prog = open('guest.vm', 'rb').read()
r = [0] * 256

class DoneExecuting(Exception):
    pass

def ret(n):
    raise DoneExecuting("done: %d" % n)

def run_with_manip(code, manip):
    input = [0] + code
    output = [0] * 16
    try:
        exec(open('interp.txt', 'r').read(), globals(), locals())
    except DoneExecuting:
        pass
    return output

ident = bytes([137, 122, 105, 96])
from pwn import *

s = remote('62.210.125.243', 1337)
sig = s.recvn(4)
assert sig == b'STIC'

def encrypt(payload):
    code = list(payload[:8])
    final = [0] * 16
    for pos in range(8, 16):
        manip = final[:]
        for i in range(256):
            manip[pos] = i
            s.send(b'\x00' + bytes(run_with_manip(code, manip)) + ident)
        winner = None
        for i in range(256):
            resp = s.recvn(1)
            if resp[0] in (1, 2):
                dec = s.recvn(16)
                if dec[pos] == payload[pos]:
                    winner = i
            else:
                raise Exception("decryption fail :(")

        print(f"{pos=}; {winner=}")
        assert winner is not None
        final[pos] = winner
    return bytes(run_with_manip(code, final))

files = [
    '6FC51949A75BFA98',
    '583C5E51D0E1AB05',
    '675160EFED2D139B',
    '08ABDA216C40B90C',
    '1D0DFAA715724B5A',
    '3A8AD6D7F95E3487',
    '325149E3FC923A77',
    '46DCC15BCD2DB798',
    '4CE294122B6BD2D7',
    '4145107573514DCC',
    '675B9C51B9352849',
    '3B2C4583A5C9E4EB',
    '58B7CBFEC9E4BCE3',
    '272FED81EAB31A41',
    'FBDF1AF71DD4DDDA',
    'ED6787E18B12543E',
    '68963B6C026C3642',
    '6811AF029018505F',
    '59BDD204AA7112ED',
    '75EDFF360609C9F7',
    'D603C7E177F13C40',
]

for fid in files:
    code = bytes.fromhex(fid)[::-1]
    enc = encrypt(code + b'\0' * 8)
    print("encryption:", enc.hex())
    s.send(b'\x01' + enc + ident)
    res = s.recvn(1)[0]
    if res == 3:
        key = s.recvn(16)
        print("file %s: key = %s" % (fid, key.hex()))
    else:
        print("file %s: error %d" % (fid, res))
