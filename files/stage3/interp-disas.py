from collections import deque
import struct

prog = open('guest.vm', 'rb').read()
def unpack(fmt, addr):
    res = struct.unpack_from('>' + fmt, prog, addr)
    if len(res) == 1:
        return res[0]
    return res

todo = deque([0])
seen = set()
data = []
while todo:
    pc = todo.popleft()
    if pc in seen or pc < 0 or pc >= len(prog):
        continue
    print(f'"{pc:6x}:"; ', end=' ')
    seen.add(pc)
    opc = prog[pc]

    if opc == 0xd9:
        dest = unpack('I', pc+1)
        print(f'# jmp {dest:#x}')
        todo.appendleft(dest)
        continue

    if opc == 0xf:
        dest = unpack('I', pc+1)
        print(f'# jne r{prog[pc+5]}, r{prog[pc+6]}, {dest:#x}')
        todo.append(dest)
        pc += 7
    elif opc == 0xd0:
        ra, rb, off, rd = unpack('BBIB', pc+1)
        print(f'r[{rd}] = prog[256*r[{ra}] + r[{rb}] + {off:#x}]')
        if (off, 65536) not in data:
            data.append((off, 65536))
        pc += 8
    elif opc == 0x6c:
        ra, off, rd = unpack('BIB', pc+1)
        print(f'r[{rd}] = prog[r[{ra}] + {off:#x}]')
        if (off, 256) not in data:
            data.append((off, 256))
        pc += 7
    elif opc == 0xd2:
        print(f'ret({prog[pc+1]})')
        continue

    elif opc == 0xd7:
        print(f'r[{prog[pc+3]}] = r[{prog[pc+1]}] >> {prog[pc+2]}')
        pc += 4
    elif opc == 0x49:
        print(f'r[{prog[pc+3]}] = r[{prog[pc+1]}] << {prog[pc+2]}')
        pc += 4
    elif opc == 0x1d:
        print(f'r[{prog[pc+3]}] = r[{prog[pc+1]}] & r[{prog[pc+2]}]')
        pc += 4
    elif opc == 0x8b:
        print(f'r[{prog[pc+3]}] = r[{prog[pc+1]}] ^ r[{prog[pc+2]}]')
        pc += 4
    elif opc == 0x65:
        print(f'r[{prog[pc+3]}] = r[{prog[pc+1]}] | r[{prog[pc+2]}]')
        pc += 4
    elif opc == 0x64:
        print(f'r[{prog[pc+3]}] = rol(r[{prog[pc+1]}], {prog[pc+2]})')
        pc += 4

    elif opc == 0xde:
        print(f'r[{prog[pc+2]}] = r[{prog[pc+1]}]')
        pc += 3
    elif opc == 0x10:
        print(f'r[{prog[pc+2]}] = r[{prog[pc+1]}] >> 4')
        pc += 3
    elif opc == 0x51:
        print(f'r[{prog[pc+2]}] = r[{prog[pc+1]}] & 0xf')
        pc += 3

    elif opc == 0x15:
        print(f'r[{prog[pc+2]}] = input[{prog[pc+1]}]')
        pc += 3
    elif opc == 0x23:
        print(f'output[{prog[pc+1]}] = r[{prog[pc+2]}]')
        pc += 3
    elif opc == 0x3f:
        print(f'r[{prog[pc+2]}] = {prog[pc+1]}')
        pc += 3

    else:
        print(f'!! unk{opc:02x} !!')
        pc += 1
    todo.appendleft(pc)
