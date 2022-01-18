#!/usr/bin/python3

data = open("login.xlsx.enc", "rb").read()
counter = 0
supersecure = list(b"SUPERSECURE")

new_data = []
for byt in data:
    new_data.append(byt - supersecure[counter % 0xb])
    counter += 1

print(new_data) # Cyber chef -> from decimal -> save file (: