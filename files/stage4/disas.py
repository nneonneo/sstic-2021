f = bytearray(b'A' * 4096 + open('pwcheck.prog', 'rb').read())
key = bytes.fromhex('0e 03 05 0a 08 04 09 0b 00 0c 0d 07 0f 02 06 01')
for i in range(0x1100, 0x1300):
    f[i] ^= key[i % 16]

pc = 0x1000

while pc < 0x1300:
    cmd = f[pc:pc+4]
    suffix = {0: '.b', 1: '.w', 2: '.d', 3: '.q', 4: '.o', 7: ''}[cmd[0] >> 4]
    opc = ['add', 'sub', 'ldi', 'and', 'or', 'xor', 'shr', 'shl', 'mul', 'cmp', 'lanerot', 'ret', 'jmp', 'call', 'ld', 'st'][cmd[0] & 0xf]
    flags = cmd[1]
    opn = cmd[2] + (cmd[3] << 8)
    if (flags & 3) == 0:
        opns = f"[r{opn}]"
    elif (flags & 3) == 1:
        opns = f"[0x{opn:x}]"
    elif (flags & 3) == 2:
        opns = f"r{opn}"
    elif (flags & 3) == 3:
        opns = f"0x{opn:x}"

    rn = (flags >> 2) & 7
    if opc == 'cmp':
        opc += ['eq', 'lt', 'gt', 'le', 'ge'][flags >> 5]
    elif opc == 'jmp':
        opc = ['jmp', 'jany0', 'jmp2', 'jany1', 'jmp4', 'jall0', 'jmp6', 'jall1'][flags >> 5]
    elif flags >> 5:
        opc += f'[{flags}]'

    print(f'{pc:04x}: {cmd.hex()} {opc}{suffix} r{rn}, {opns}')
    pc += 4
