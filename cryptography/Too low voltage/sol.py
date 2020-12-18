#!/usr/bin/env python3

from hashlib import sha256
from binascii import unhexlify
from Crypto.Util.number import *
import string
import re
from pwn import *

m_sign = "0123456789abcdef"
e = 65537

signature_pattern  = re.compile("signature: (.*)\n\n")
modulus_pattern  = re.compile("n:(.*)\n")
message_pattern  = re.compile("b'(.*)'\n")
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

def verify_signature(s,e,n):
	return long_to_bytes(pow(s,e,n)).hex() == m_sign

def get_key(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    d_p = inverse(e, p - 1)
    d_q = inverse(e, q - 1)
    inv_q = inverse(q, p)

    pubkey = (n, e)
    privkey = (p, q, d_p, d_q, inv_q)

    return (pubkey, privkey)

def my_sign(msg, privkey):
	p, q, _, _, _ = privkey
	d = inverse(e, (p-1)*(q-1))
	return(pow(msg,d,modulus))

r = remote("challs.xmas.htsp.ro", 1006)
proof_of_work = r.recvuntil("\n").split(b"=")[1].strip().decode()
r.sendline(PoW(proof_of_work))
s = r.recvuntil("exit\n\n")
modulus = int(modulus_pattern.search(s.decode()).group(1), 16)
for i in range(60):

	r.sendline("1")
	r.recv()
	print( f"[*] Collecting {i}' signature and checking for faulty one..")
	r.sendline(m_sign)
	s = r.recv()
	candidate = int(signature_pattern.search(s.decode()).group(1), 16)
	if verify_signature(candidate,e,modulus):
		correct_signature = candidate
	elif i:
		p = GCD(modulus, correct_signature - candidate)
		q = modulus // p
		if p*q == modulus:
			print(f"one factor is found:\np = {p}\nq = {q}\np*q == modulus : {p*q == modulus}")
			break
try:
	_, private_key = get_key(q, p)
	r.sendline("2")
	s = r.recv()
	message = int(message_pattern.search(s.decode()).group(1), 16)
	r.sendline(hex(my_sign(message, private_key))[2:])
	print(r.recv())

except Exception as e:
	print(f"think harder :p {e}")