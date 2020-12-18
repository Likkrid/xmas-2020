#!/usr/bin/env python3
import time
from pwn import *

def totalPrimeFactors(n):
    count = 0;

    if ((n % 2) == 0):
        count += 1;
        while ((n % 2) == 0):
            n //= 2;

    i = 3;
    while (i * i <= n):

        if ((n % i) == 0):
            count += 1;
            while ((n % i) == 0):
                n //= i;
        i += 2;

    if (n > 2):
        count += 1;

    return count;

# function to count number
# of pair with given GCD and LCM
def countPairs(G, L):

    if (L % G != 0):
        return 0;

    div = int(L // G);

    return (1 << totalPrimeFactors(div));

r = remote("challs.xmas.htsp.ro", 6050)
welcome = r.recvuntil("1/100\n")
pwned = False
while True:
    gcd = int(r.recvuntil("\n").split(b"=")[1].strip())
    lcm = int(r.recvuntil("\n").split(b"=")[1].strip())

    r.sendline(str(countPairs(gcd, lcm)))
    print(r.recvline())
    if pwned:
        print(r.recvall())
    check = r.recvuntil("100\n")
    print(check)
    if b"100/100" in check:
        pwned = True


