from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import *
import os

pcap_cipher = "53616e74612773313333374956343230ab0c288b0ae26eaf8adbcf00bddf35fa"

########
#Testing
########
# KEY = b'\xb7\xda\x9c\x1d\xf5\x19{\xfa[\xe9\x02\xaeJ\x84Q\x1d'


# def cbc_encrypt(iv, plain):
# 	iv = bytes.fromhex(iv)
# 	padded = pad(plain, 16)
# 	cipher = AES.new(KEY, AES.MODE_CBC, iv)
# 	encrypted = cipher.encrypt(padded)
# 	ciphertext = iv.hex() + encrypted.hex()

# 	return ciphertext

# def cbc_decrypt(ciphertext):
#     iv = bytes.fromhex(ciphertext[:32])
#     try:
#         cipher = AES.new(KEY, AES.MODE_CBC, iv)
#         decrypted = cipher.decrypt(bytes.fromhex(ciphertext[32:]))
#         unpadded = unpad(decrypted, 16)
#         return unpadded
#     except Exception as e:
#     	return e

# test = b"ls"
# proof_of_enc = cbc_encrypt(pcap_cipher[:32], test)
# proof_of_dec = cbc_decrypt(proof_of_enc)

# print(f"\nencrypted \"{test.decode()}\" with IV: {pcap_cipher[:32]}: {proof_of_enc},\ndecrypted with same IV and KEY: {proof_of_dec}\n")

# forgery = xor(bytes.fromhex(pcap_cipher[:32]),pad(b"ls", 16),pad(b"echo ok", 16)).hex()+pcap_cipher[32:]
# print(forgery)
# print(cbc_decrypt(forgery))

# sample = "53616e74612773313333374956343230af459d65b2c9174068a5de3dba2be67d"
#pwd
#whoami
#echo
#lsblk
##########

forgery = xor(bytes.fromhex(pcap_cipher[:32]),pad(b"ls", 16),pad(b"echo \"$(<nice)\"", 16)).hex()+pcap_cipher[32:]

r = remote("challs.xmas.htsp.ro", 1002)
r.recv()
r.sendline(forgery)
print(r.recv())