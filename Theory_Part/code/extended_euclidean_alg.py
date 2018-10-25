#!/usr/bin/env pathon3
import numpy as np

# N, a = 49, 37
N, a = 5, 1

AN, Aa = np.array([1, 0]), np.array([0, 1])

N_org, a_org = N, a

flag = True
if N < a:
    Q = a // N
    a = a % N
    Aa -= Q * AN
    if a == 1 or a == 0:
        flag = False

print('Q', N, a, AN, Aa)
while flag:
    Q = N // a
    N = N % a
    AN -= Q * Aa
    print(Q, N, a, AN, Aa)
    if N == 1 or N == 0:
        break

    Q = a // N
    a = a % N
    Aa -= Q * AN
    print(Q, N, a, AN, Aa)
    if a == 1 or a == 0:
        break

if N == 0 or a == 0:
    print('no multiplicative inverse')

if N == 1:
    print('1=', AN[0], '*', N_org, '+', AN[1], '*', a_org)
elif a == 1:
    print('1=', Aa[0], '*', N_org, '+', Aa[1], '*', a_org)
