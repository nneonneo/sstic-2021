prog = open('guest.vm', 'rb').read()
r = [0] * 256

class DoneExecuting(Exception):
    pass

def ret(n):
    raise DoneExecuting("done: %d" % n)

def run(input):
    input = [0] + input
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

def test(input):
    output = run(input)
    s.send(b'\x00' + bytes(output) + ident)
    resp = s.recvn(1)
    assert resp[0] in (1, 2)
    dec = s.recvn(16)
    return dec.hex()

while 1:
    pause()
    print(test([0x22, 0x11, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88] + [0xff] * 8))
