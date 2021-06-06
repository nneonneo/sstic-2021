from pwn import *
import sys

s = remote('62.210.125.243', 1337)
sig = s.recvn(4)
assert sig == b'STIC'
 
# key obtained through the stage3 whitebox crypto exploit, needs to be refreshed each hour
key = bytes.fromhex('0d548ffc7f5f517743387e1d6477ea75f8bf6a60')

def run_prog(prog, data):
    s.send(b'\x02' + key)
    s.send(p64(len(prog)))
    s.send(prog)
    s.send(p64(len(data)))
    s.send(data)
    s.send(p64(0x1000))

    res = s.recvn(1)
    if res[0] == 8:
        output = s.recvn(0x1000)
        print("output:", output.rstrip(b'\0').hex())
        r = s.recvuntil('---DEBUG LOG END---\n').decode('latin1')
        print(r)
    else:
        raise Exception("program failed, error %d" % res[0])
