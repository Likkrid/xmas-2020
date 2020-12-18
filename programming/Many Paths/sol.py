#!/usr/bin/env python3

import numpy as np
import re
from pwn import *

from numpy.core.numeric import concatenate, isscalar, binary_repr, identity, asanyarray, dot
from numpy.core.numerictypes import issubdtype
def matrix_power(M, n, mod_val):
    M = asanyarray(M)
    if len(M.shape) != 2 or M.shape[0] != M.shape[1]:
        raise ValueError("input  must be a square array")
    if not issubdtype(type(n), int):
        raise TypeError("exponent must be an integer")

    from numpy.linalg import inv

    if n==0:
        M = M.copy()
        M[:] = identity(M.shape[0])
        return M
    elif n<0:
        M = inv(M)
        n *= -1

    result = M % mod_val
    if n <= 3:
        for _ in range(n-1):
            result = dot(result, M) % mod_val
        return result

    beta = binary_repr(n)
    Z, q, t = M, 0, len(beta)
    while beta[t-q-1] == '0':
        Z = dot(Z, Z) % mod_val
        q += 1
    result = Z
    for k in range(q+1, t):
        Z = dot(Z, Z) % mod_val
        if beta[t-k-1] == '1':
            result = dot(result, Z) % mod_val
    return result % mod_val

destination_pattern = re.compile("N = (.*)\n")
l_pattern  = re.compile("L = (.*)\n")



r = remote("challs.xmas.htsp.ro", 6053)
s = r.recv()

i = 0
while True:
    raw_adjacency_matrix = re.findall(r"([0-1,]+)\n",s.decode())[1:]
    n = int(destination_pattern.search(s.decode()).group(1))
    l = int(l_pattern.search(s.decode()).group(1))

    formatted_adjacency_matrix = [ [int(n) for n in raw_adjacency_matrix[i].split(",") if "," in raw_adjacency_matrix[i] ] for i in range(len(raw_adjacency_matrix)) ]
    formatted_adjacency_matrix = [ x for x in formatted_adjacency_matrix if x != []]

    m = np.array(formatted_adjacency_matrix)
    lth_adjacency_matrix = matrix_power(m, l, 666013)
    walks = str(lth_adjacency_matrix[0][n-1])

    r.sendline(walks)
    r.clean()
    try:
        s = r.recvuntil("\n\n")
    except:
        s = r.recv()
    print(s)