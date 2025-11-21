import datetime, sys
from primeModulusHandler import PrimeModulusHandler

class AesEncryption:
    def __init__(self, key, encoding): # key must be in ascii
        self._primeModulusHandler= PrimeModulusHandler()
        self.rcon = [1,2,4,8,16,32,64,128,27,54]

        try:
            if int(encoding) in [8, 16, 32]:
                self.bits_per_letter = int(encoding)
                self.letters_per_block = 128 // self.bits_per_letter
            else:
                raise Exception()
        except:
            raise Exception("Invalid AesEncryption instantiation - pick a value of bits from 8, 16, 32")

        self.set_key(key)

        self.sbox = {}
        self.inverse_sbox = {}
        for i in range(256):
            self.sbox[i] = self.rijndael_sbox(i)
            self.inverse_sbox[i] = self.rijndael_inverse_sbox(i)


    def set_key(self, key): # key in ascii
        block = [[],[],[],[]]
        for column in range(0, 16, 4):
            for offset in range(0, 4):
                block[column // 4].append(ord(key[column + offset]))
        self.key = block


    def rijndael_sbox(self, num):
        if num == 0: return 99 # special case
        A = [[1,0,0,0,1,1,1,1],[1,1,0,0,0,1,1,1],[1,1,1,0,0,0,1,1],[1,1,1,1,0,0,0,1],[1,1,1,1,1,0,0,0],[0,1,1,1,1,1,0,0],[0,0,1,1,1,1,1,0],[0,0,0,1,1,1,1,1]]
        b = "11000110"
        inv_num = self._primeModulusHandler.multiplicative_inverse_in_gf8(num)
        return self._primeModulusHandler.affine_transformation(A, inv_num, b)

    def rijndael_inverse_sbox(self, num):
        if num == 99: return 0 # special case
        A = [[0,0,1,0,0,1,0,1],[1,0,0,1,0,0,1,0],[0,1,0,0,1,0,0,1],[1,0,1,0,0,1,0,0],[0,1,0,1,0,0,1,0],[0,0,1,0,1,0,0,1],[1,0,0,1,0,1,0,0],[0,1,0,0,1,0,1,0]]
        b = "10100000"
        inv_num = self._primeModulusHandler.affine_transformation(A, num, b)
        return self._primeModulusHandler.multiplicative_inverse_in_gf8(inv_num)

    def mix_columns(self, block):
        # matrix [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
        # Using fast implementation from The Design of Rijndael 4.1.2
        for column in block:
            t = column[0] ^ column[1] ^ column[2] ^ column[3]
            u = column[0]

            column[0] ^= self._primeModulusHandler.multiply_in_gf8(column[0] ^ column[1], 2) ^ t
            column[1] ^= self._primeModulusHandler.multiply_in_gf8(column[1] ^ column[2], 2) ^ t
            column[2] ^= self._primeModulusHandler.multiply_in_gf8(column[2] ^ column[3], 2) ^ t
            column[3] ^= self._primeModulusHandler.multiply_in_gf8(column[3] ^ u, 2) ^ t

    def inverse_mix_columns(self, block):
        # matrix [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
        # Using fast implementation from The Design of Rijndael 4.1.3
        for column in block:
            u = self._primeModulusHandler.multiply_in_gf8(self._primeModulusHandler.multiply_in_gf8(column[0] ^ column[2], 2), 2)
            v = self._primeModulusHandler.multiply_in_gf8(self._primeModulusHandler.multiply_in_gf8(column[1] ^ column[3], 2), 2)
            column[0] ^= u
            column[1] ^= v
            column[2] ^= u
            column[3] ^= v

        self.mix_columns(block)

    def shift_rows(self, block):
        block[0][1], block[1][1], block[2][1], block[3][1] = block[1][1], block[2][1], block[3][1], block[0][1]
        block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
        block[0][3], block[1][3], block[2][3], block[3][3] = block[3][3], block[0][3], block[1][3], block[2][3]

    def inverse_shift_rows(self, block):
        block[0][1], block[1][1], block[2][1], block[3][1] = block[3][1], block[0][1], block[1][1], block[2][1]
        block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
        block[0][3], block[1][3], block[2][3], block[3][3] = block[1][3], block[2][3], block[3][3], block[0][3]

    def sub_bytes(self, block):
        for column in range(4):
            for row in range(4):
                block[column][row] = self.sbox[block[column][row]]

    def inverse_sub_bytes(self, block):
        for column in range(4):
            for row in range(4):
                block[column][row] = self.inverse_sbox[block[column][row]]

    def next_key(self, block, rcon):
        resultant_block = [[],[],[],[]]

        for row in range(4):
            resultant_block[0].append(block[0][row] ^ self.sbox[block[3][(row + 1) % 4]] ^ rcon[row])

        for column in range(1,4):
            for row in range(4):
                resultant_block[column].append(block[column][row] ^ resultant_block[column - 1][row])

        return resultant_block

    def add_round_key(self, block, round_key):
        for column in range(4):
            for row in range(4):
                block[column][row] ^= round_key[column][row]

    def encrypt(self, data):
        encrypted_data = ""
        round_keys = []

        block = self.next_key(self.key, [self.rcon[0],0,0,0])
        round_keys.append(block)

        for i in range(1,10):
            block = self.next_key(block, [self.rcon[i], 0, 0, 0])
            round_keys.append(block)

        for i in range(0, len(data), self.letters_per_block):
            str_data = data[i:i+self.letters_per_block]
            binary = ""
            for letter in list(str_data):
                binary += self._primeModulusHandler.get_bit_pattern(ord(letter), self.bits_per_letter)
            binary += "0" * (128 - len(binary))
            block = [[],[],[],[]]
            for column in range(0, 128, 32):
                for offset in range(0, 32, 8):
                    block[column // 32].append(int(binary[column+offset:column+offset+8], 2))

            self.add_round_key(block, self.key)
            for round in range(9):
                self.sub_bytes(block)
                self.shift_rows(block)
                self.mix_columns(block)
                self.add_round_key(block, round_keys[round])

            self.sub_bytes(block)
            self.shift_rows(block)
            self.add_round_key(block, round_keys[9])
            
            for column in range(4):
                for row in range(4):
                    encrypted_data += chr(block[column][row])

        return encrypted_data


    def decrypt(self, data):
        decrypted_data = ""
        round_keys = []

        block = self.next_key(self.key, [self.rcon[0],0,0,0])
        round_keys.append(block)

        for i in range(1,10):
            block = self.next_key(block, [self.rcon[i], 0, 0, 0])
            round_keys.append(block)

        for i in range(0, len(data), 16):
            str_data = data[i:i+16]
            binary = ""
            for letter in list(str_data):
                binary += self._primeModulusHandler.get_bit_pattern(ord(letter))
            binary += "0" * (128 - len(binary))
            block = [[],[],[],[]]
            for column in range(0, 128, 32):
                for offset in range(0, 32, 8):
                    block[column // 32].append(int(binary[column+offset:column+offset+8], 2))

            self.add_round_key(block, round_keys[9])
            self.inverse_shift_rows(block)
            self.inverse_sub_bytes(block)
            for round in range(8, -1, -1):
                self.add_round_key(block, round_keys[round])
                self.inverse_mix_columns(block)
                self.inverse_shift_rows(block)
                self.inverse_sub_bytes(block)

            self.add_round_key(block, self.key)
            
            decrypted_part = ""
            for column in range(4):
                for row in range(4):
                    decrypted_part += self._primeModulusHandler.get_bit_pattern(block[column][row])
            
            for o in range(0, 128, self.bits_per_letter):
                decrypted_data += chr(int(decrypted_part[o:o+self.bits_per_letter], 2))


        return decrypted_data

aes = AesEncryption("aesEncryptionKey", 32)

message = "hello world. How are you doing on this fine evening. Would you like to go somewhere today? I know, lets go to school"

message = open("heart-of-darkness.txt", "r").read()

start = datetime.datetime.now()
print(message)
e_message = aes.encrypt(message)
print("e:",e_message)
d_message = aes.decrypt(e_message)
print("d:",d_message)
end = datetime.datetime.now()
print(end - start)

"""tests:
aes = AesEncryption()

b1 = [[43,40,171,9],[126,174,247,207],[21,210,21,79],[22,166,136,60]]

for i in range(10):
    b1 = aes.next_key(b1, [aes.rcon[i], 0, 0, 0])

print(b1)

---------

block = [[int("d4", 16),int("e0", 16),int("b8", 16),int("1e", 16)],[int("bf", 16),int("b4", 16),int("41", 16),int("27", 16)],[int("5d", 16),int("52", 16),int("11", 16),int("98", 16)],[int("30", 16),int("ae", 16),int("f1", 16),int("e5", 16)]]
print(aes.inverse_mix_columns(aes.mix_columns(block)))

---------

message = ""
for i in ["32", "88", "31", "e0", "43", "5a", "31", "37", "f6", "30", "98", "07", "a8", "8d", "a2", "34"]:
    message += chr(int(i, 16))
key = ""
for i in ["2b", "28", "ab", "09", "7e", "ae", "f7", "cf", "15", "d2", "15", "4f", "16", "a6", "88", "3c"]:
    key += chr(int(i, 16))

print(message)
print(key)

aes = AesEncryption(key, 8)
e_message = aes.encrypt(message)
print(e_message)


d_message = aes.decrypt(e_message)
print(d_message)

---------
"""
