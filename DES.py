#-*- coding: utf8 -*-
# Hill Cipher By 3ND

from base64 import b64encode

ENC, DEC = 1, 0

# 初始置换 IP
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# 逆初始置换 PI
PI = [40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25]

# 拓展置换 E / E-盒 / 扩散
# 32-bit -> 8 * 4-bit -> 8 * 6-bit -> 48-bit
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# 初始密钥置换 PC-1 / 64-bits -> 56-bits
PC_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# 密钥左移位数
SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# 轮密钥置换 PC-2 / 返回 key_i
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# S-盒 / 混淆
S_BOX = [        
[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
],
[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
],
[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
],
[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
],  
[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
], 
[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
], 
[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
], 
[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
]

# f 函数中每轮 S-盒 替换后的置换操作
P = [16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25]

# 分割列表 s 为 n 个子列表
def nsplit(s, n):
    return [s[k:k + n] for k in range(0, len(s), n)]

# 转化给定的字符串转换为特定大小的二进制值
def binvalue(val, bitsize):
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "[?]Exception:二进制值超出预期大小({})".format(binval)
    while len(binval) < bitsize:
        binval = "0" + binval # 填充 0 
    return binval

# 字符串/数组转化为二进制数组
def str2bin(text):
    array = list()
    for char in text:
        # 1-byte -> 8-bits
        binval = binvalue(char, 8)
        # 逐位加入返回数组
        array.extend([int(x) for x in list(binval)])
    return array

# 二进制数组转化为字符串
def bin2str(array):
    # 二进制数组 8-bits -> 1-byte, 转化为字符串返回
    res = ''.join([chr(int(y,2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in  nsplit(array,8)]])   
    return res

class DES():
    # 初始化函数 __init__()
    def __init__(self):
        self.key = None
        self.text = None
        self.keys = list()
    
    # 初始置换 IP / 逆初始置换 PI
    def permut(self, block, table):
        return [block[x-1] for x in table]

    # 拓展置换 E / 扩散
    def expand(self, block, table):
        return [block[x-1] for x in table]
    
    # S-盒置换 / 混淆
    def sbox_substitute(self, R_e):
        subblocks = nsplit(R_e, 6) # 48-bits -> 8 * 6-bits
        result = list()
        for i in range(len(subblocks)):
            block = subblocks[i]
            # MSB block[0] + LSB block[5] -> 行号(Binary)
            row = int(str(block[0]) + str(block[5]), 2)
            # block[2, 3, 4, 5] -> 列号(Binary)
            column = int(''.join([str(x) for x in block[1:-1]]), 2)
            # 第 i 轮 S-盒 的置换值 val
            val = S_BOX[i][row][column]
            # 6-bits -> 4-bits
            bin = binvalue(val, 4)
            # 加入返回列表
            result += [int(x) for x in bin]
        return result

    # 密钥编排 / 密钥生成
    def generatekeys(self):
        self.keys = []
        key = str2bin(self.key)
        # PC-1 置换
        key = self.permut(key, PC_1)
        # 56-bits -> 2 * 28-bits
        L, R = nsplit(key, 28)
        for i in range(16):
            # 每轮的密钥移位
            L, R = self.shift(L, R, SHIFT[i])
            # 合并 Left / Right 
            overall = L + R
            # 变换完成后存储 Key_i
            self.keys.append(self.permut(overall, PC_2))

    # 异或运算 - 列表
    def xor(self, l1, l2):
        return [x ^ y for x, y in zip(l1, l2)]

    # 密匙编排中的移位运算
    def shift(self, L, R, n):
        return L[n:] + L[:n], R[n:] + R[:n]
    
    # PKCS5 模式填充
    def addPadding(self):
        pad_len = 8 - (len(self.text) % 8)
        self.text += pad_len * chr(pad_len)
    
    # 去除填充的明文文本
    def removePadding(self, data):
        pad_len = ord(data[-1])
        return data[:-pad_len]
    
    # 加密
    def encrypt(self, key, text, padding=False):
        return self.calc(key, text, ENC, padding)
    
    # 解密
    def decrypt(self, key, text, padding=False):
        return self.calc(key, text, DEC, padding)

    # 执行加密和解密
    def calc(self, key, text, action=ENC, padding=False):
        if len(key) < 8:
            raise "[?]Exception:密钥长度需要为 8-bits"
        # 密钥长度 > 8 则截断多余部分
        elif len(key) > 8:
            key = key[:8]
        # 初始化参数
        self.key = key
        self.text = text
        # 是否进行文本填充
        if padding and action == ENC:
            self.addPadding()
        # 未进行填充操作，则指定的数据大小必须为 n * 8-bits
        elif len(self.text) % 8 != 0:#
            raise "[?]Exception:密钥大小不是 n * 8-bits"
        # 生成密钥
        self.generatekeys()
        # 将待加密和解密的文本转化为 8-bytes -> 64-bits
        text_blocks = nsplit(self.text, 8)
        result = list()
        for block in text_blocks:
            block = str2bin(block)
            # 初始置换 IP()
            block = self.permut(block, IP)
            # 64-bits -> L 32-bits + R 32-bits
            L, R = nsplit(block, 32)
            tmp = None
            # Feistel 中的 16 轮运算
            for i in range(16):
                # 右半部分进行拓展置换 E 进行扩散
                # 32-bits -> 48-bits 用于与 Key_i 结合
                R_e = self.expand(R, E)
                # 异或运算
                if action == ENC: # 加密操作从前往后选择密钥
                    tmp = self.xor(self.keys[i], R_e)
                else: # 如果是解密则从后往前选择 Key
                    tmp = self.xor(self.keys[15-i], R_e)
                # f函数中 S-盒替换 进行混淆
                tmp = self.sbox_substitute(tmp)
                # f 函数中的 P 置换
                tmp = self.permut(tmp, P)
                # 左半部分 L 与 f 函数的输出进行异或运算
                tmp = self.xor(L, tmp)
                # 左右两部分进行置换
                L = R
                R = tmp
            # 最后进行初始 IP 置换的 逆置换
            result += self.permut(R + L, PI)
        # 二进制转化为字符串
        final_res = bin2str(result)
        # 填充数据的处理
        if padding and action == DEC: # 解密操作获取的明文去除填充数据
            return self.removePadding(final_res) 
        else: # 返回最后的结果(解密->明文，加密->密文)
            return final_res 
    
if __name__ == '__main__':
    Key = raw_input("Please Input Key >> ")
    #Key = "ABC123!@"
    Plain = raw_input("Please Input Plain >> ")
    #Plain = "NiceDES!"
    C = DES()
    Cipher = C.encrypt(Key, Plain, padding=True)
    Plian_Dec = C.decrypt(Key, Cipher, padding=True)
    print "Key: %s" % Key[:8]
    print "Plain Text: %s" % Plain
    print "Ciphered Text: %s" % b64encode(Cipher)
    print "Deciphered: %s" % Plian_Dec