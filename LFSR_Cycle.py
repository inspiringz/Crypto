#-*- coding: utf-8 -*-
# 本原多项式样本值 (0, 1, 3, 5, 16)
from operator import eq

def LFSR(p_x, seq):
    s = 0
    for i in p_x:
        s ^= seq[i - 1]
    for i in range(len(seq) - 1):
        seq[i] = seq[i + 1]
    seq[-1] = s

if __name__ == "__main__":
    # 特征多项式 P(x)
    # P_x = list(input("Please Input P(x) >> "))
    # 本源多项式
    P_x = list((0, 1, 3, 5, 16))
    p_x = P_x[1:]
    # seq = input("Please Input Sequence >> ")
    # 寄存器的初始状态 seq
    seq = [(_ % 2) for _ in range(P_x[-1])]
    cmp = [(_ % 2) for _ in range(P_x[-1])]
    cnt = 0
    while True:
        LFSR(p_x, seq)
        cnt += 1
        if eq(seq, cmp):
            print seq
            print cnt
            break