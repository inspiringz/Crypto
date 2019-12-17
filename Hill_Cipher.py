#-*- coding: utf-8 -*-
# Hill Cipher By 3ND
import sympy as sp

alpha26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def stringToMatrix(string, alpha, size):
    rows = [[] for _ in range(size)]
    for i in range(len(string)-1): # -1 Remove /r
        rows[i % size].append(alpha.index(string[i]))
    return sp.Matrix(rows)

def matrixToString(matrix, alpha, size):
    string = ""
    for i in range(matrix.cols):
        for j in matrix.col(i):
            string += alpha[j % len(alpha)]
    return string

def encrypt(plain, key_enc, alpha):
    key_enc = sp.Matrix(key_enc)
    # Calculate the Determinant and Check if there is a solution
    D = key_enc.det()
    if sp.gcd(D, 26) != 1:
        print "Not relatively prime. No solution!"
        exit()
    # Convert plain text to Matrix to Encrypt
    mat_plain = stringToMatrix(plain, alpha, key_enc.shape[0])
    # Calculate the Cipher Matrix
    mat_cipher = key_enc * mat_plain
    # Calculate the Cipher
    cipher = matrixToString(mat_cipher, alpha, key_enc.shape[0])
    return cipher

def decrypt(cipher, key_dec, alpha):
    key_dec = sp.Matrix(key_dec)
    mat_cipher = stringToMatrix(cipher, alpha, key_dec.shape[0])
    mat_plain = key_dec * mat_cipher
    plain = matrixToString(mat_plain, alpha, key_dec.shape[0])
    return plain

def crack(cipher, key_enc, alpha):
    # Konw Cipher and Key_Enc to Crack Plain
    key_enc = sp.Matrix(key_enc)
    # Calculate the Key_Dec 
    key_dec = key_enc.inv_mod(len(alpha))
    key_dec = key_dec.applyfunc(lambda x: x % len(alpha))
    return encrypt(cipher, key_dec, alpha)


if __name__=="__main__":
    # Input Plain Text
    plain = raw_input("Input Plain Text >> ")
    # plian = 'ACT'
    # Input Key to Encrypt
    key_enc = input("Input Your Key Matrix >> ")
    key_enc = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
    # Encrypt
    print encrypt(plain, key_enc, alpha26)
    # POH
    # Input Cipher Text
    cipher = raw_input("Input Cipher Text >> ")
    # cipher = POH
    key_dec = input("Input Your Key Matrix >> ")
    key_dec = [[8, 5, 10], [21, 8, 21], [21, 12, 8]]
    print decrypt(cipher, key_dec, alpha26)
    # ACT
    # Input Cipher to Crack
    cipher = raw_input("Input Cipher Text (Crack)>> ")
    # Input the Key_Enc Matrix
    key_enc = input("Input Your Key_Enc Matrix >> ")
    key_enc = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
    print crack(cipher, key_enc, alpha26)
