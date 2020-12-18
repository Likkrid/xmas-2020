#!/usr/bin/env python3
from pwn import *
import re

array_pattern  = re.compile("array = \[(.*)\]\n")
k1_pattern  = re.compile("k1 = (.*)\n")
k2_pattern = re.compile("k2 = (.*)\n")

r = remote("challs.xmas.htsp.ro", 6051)
s = r.recv(1024)
print(s)


while True:
	array = sorted([int(i) for i in (array_pattern.search(s.decode()).group(1).split(","))])
	k1 = int(k1_pattern.search(s.decode()).group(1))
	k2 = int(k2_pattern.search(s.decode()).group(1))
	payload = ", ".join(str(i) for i in array[:k1])
	payload += ";"
	payload += ", ".join(str(i) for i in array[::-1][:k2])
	r.sendline(payload)
	r.clean()
	s = r.recvrepeat(0.3)
	print(s)
