#!/usr/bin/env python3

from hashlib import sha256
from binascii import unhexlify
from Crypto.Util.number import *
import string
import re
from pwn import *

message_pattern  = re.compile("message: (.*).")
modulus_pattern  = re.compile("n: (.*)\n")
exponent_pattern = re.compile("\ne: (.*)\n")

def bulk_gcd(messages, keys):
	P = 1
	for i, n, e in keys:
	    P *= n

	for i, n, e in keys:
	    g = GCD(n, P//n)
	    if g != 1:
	        p = g
	        q = n // p
	        phi = (p-1) * (q-1)
	        d = inverse(e, phi)
	        plain = long_to_bytes(pow(messages[i],d,n)).hex()
	        print(f"[*] Pwne3d .. Decrypting message..\nmessage: {plain}")
	        return plain


def PoW(proof_of_work):
	for i in string.hexdigits:
	    for j in string.hexdigits:
	        for k in string.hexdigits:
	            for l in string.hexdigits:
	            	for m in string.hexdigits:
	            		for n in string.hexdigits:
	            			candidate = i+j+k+l+m+n
		            		if sha256(unhexlify(candidate)).hexdigest()[-5:] == proof_of_work:
		            			return (candidate)

messages = []
keys = []

while True:
	r = remote("challs.xmas.htsp.ro", 1000)
	proof_of_work = r.recvuntil("\n").split(b"=")[1].strip().decode()

	r.sendline(PoW(proof_of_work))
	r.recvuntil("exit\n")

	for i in range(150):
		print(f"[{i}] Requesting keys..")
		r.sendline("1")
		s = r.recvuntil("exit\n")
		message = int(message_pattern.search(s.decode()).group(1), 16)
		modulus = int(modulus_pattern.search(s.decode()).group(1))
		exponent = int(exponent_pattern.search(s.decode()).group(1))

		messages.append(message)
		keys.append((i, modulus, exponent))

		secret_message = bulk_gcd(messages, keys)
		if secret_message:
			r.sendline("2")
			r.recvuntil("got.\n\n")
			r.sendline(secret_message)
			print(r.recvline())
			print(r.recvline())
			exit()

#X-MAS{M4yb3_50m3__m0re_r4nd0mn3s5_w0u1d_b3_n1ce_eb0b0506}