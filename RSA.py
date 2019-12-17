# -*- coding: utf-8 -*-

from random import randrange, randint

# Miller-Rabin Primality Test
def Miller_Rabin(n, s=77):
    if n % 2 == 0:
        return False
    if n == 2 or n == 3:
        return True
    u, r = 0, n - 1
    while r % 2 == 0:
        u += 1
        r //= 2
    for _ in range(s):
        a = randrange(2, n - 2)
        z = pow(a, r, n)
        if z != 1 and z != n - 1: # j = 0
            for j in range(1, u - 1):
                z = pow(z, 2, n)
                if z == 1:
                    return False
            if z != n - 1:
                return False
    return True

# Generate l-bit Prime Number
def genPrime(l=1024):
    while True:
        # MSB(1) -> n-bit; LSB(1) Tail Odd Number 
        randm = int("1".join([str(randint(0, 1)) for _ in range(l - 2)]) + "1", 2)
        if Miller_Rabin(randm):
            return randm

# String to Hex
def str2hex(m):
    return "".join("{:02x}".format(ord(x)) for x in m)

# Extended Euclidean Algorithm
def Exgcd(r0, r1):
    # r0*si + r1*ti = ri
    if r1 == 0:
        return (1, 0, r0)
    # r0*s1 + r1*t1 = r0
    s1, t1 = 1, 0
    # r0*s2 + r1*t2 = r1
    s2, t2 = 0, 1
    while r1 != 0:
        q = r0 / r1
        # ri = r(i-2) % r(i-1)
        r = r0 % r1
        r0, r1 = r1, r
        # si = s(i-2) - q*s(i-1)
        s = s1 - q*s2
        s1, s2 = s2, s
        # ti = t(i-2) - q*t(i-1)
        t = t1 - q*t2
        t1, t2 = t2, t
    return(s1, t1, r0)

# computeD: Known phi(n) and e, calculate d
# d ≡ e'(mod phi(n))
# e: the public (or encryption) exponent
# phi_n:  Euler totient function phi(n) = (p-1)*(q-1)
def computeD(e, phi_n):
    (s, t, r) = Exgcd(phi_n, e)
    # t maybe < 0, so convert it
    return t if t > 0 else phi_n + t

# Generate the encryption index: e
# 通常来说，e 不需要太大，这样可以大幅提高加密效率。
# 我们可以生成一个素数，若它不是 φ(n) 的因数，则(e, φ(n))=1
def genE(phi_n):
    while True:
        e = genPrime(l=randint(3,13))
        if e == 3 or e == 5:
            continue
        if phi_n % e != 0:
            return e

# RSA Encryption
# Public key: (n,e)
# c ≡ m^e (mod n)
def RSAEncrypt(message, e, n):
    message = int(str2hex(message), 16)
    print "message = " + str(message)
    cipher = pow(message, e, n)
    return cipher

# RSA Decryption
# Private key: d
# m ≡ c^d (mod n)
def RSADecrypt(cipher, d, n):
    message = pow(cipher, d, n)
    message = '{:x}'.format(message).decode('hex')
    return message

def main():
    # 生成两个大素数 p 和 q
    print "[+] Generate p and q:"
    p = genPrime(512)
    q = genPrime(512)
    print "> p = " + str(p)
    print "> q = " + str(q)
    # 计算 n = p * q
    n = p * q
    print "> n = " + str(n)
    # 计算 φ(n) = (p - 1) * (q - 1)
    phi_n = (p - 1) * (q - 1)
    print "[+] Generate e Now ..."
    # 生成一个和φ(n)互素的数e
    e = genE(phi_n)
    print "> e = " + str(e)
    message = raw_input("Please Input Message >> ")
    # 加密算法
    print "[+] Encrypt Message Now ..."
    Ciphertext = RSAEncrypt(message, e, n)
    print "> Ciphertext is: " + str(Ciphertext)
    # 解密算法
    print "[+] Decrypt CipherText Now ..."
    # 使用私钥 d，d 是 e 模 φ(n) 的逆
    d = computeD(e, phi_n)
    print "> d = " + str(d)
    Plaintext = RSADecrypt(Ciphertext, d, n)
    print "> Plaintext is:" + str(Plaintext)

if __name__ == "__main__":
    main()
