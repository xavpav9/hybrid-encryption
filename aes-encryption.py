import datetime
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
        for o in range(0, 16, 4):
            for j in range(0, 4):
                block[o // 4].append(ord(key[o + j]))
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

    def mix_columns(self, block, matrix=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]):
        resultant_block = [[],[],[],[]]
        for column_number in range(4):
            column_data = [row[column_number] for row in block]
            for row_number in range(4):
                matrix_data = matrix[row_number]
                values_to_be_summed = [self._primeModulusHandler.multiply_in_gf8(column_data[i], matrix_data[i]) for i in range(4)]
                result = 0
                for data in values_to_be_summed:
                    result = result ^ data

                resultant_block[row_number].append(result)

        return resultant_block

    def inverse_mix_columns(self, block):
        return self.mix_columns(block, [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]])

    def shift_rows(self, block):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for i in range(4):
                resultant_block[row].append(block[row][(i + row) % 4])
        return resultant_block

    def inverse_shift_rows(self, block):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for i in range(4):
                resultant_block[row].append(block[row][(i - row) % 4])
        return resultant_block

    def sub_bytes(self, block):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for i in range(4):
                resultant_block[row].append(self.sbox[block[row][i]])
        return resultant_block

    def inverse_sub_bytes(self, block):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for i in range(4):
                resultant_block[row].append(self.inverse_sbox[block[row][i]])
        return resultant_block

    def next_key(self, block, rcon):
        resultant_block = [[],[],[],[]]
        column_data = []
        for i in range(4):
            column_data.append([row[i] for row in block])

        subbed_column_data = []
        for i in range(4):
            subbed_column_data.append(self.sbox[column_data[3][(i + 1) % 4]])

        first_col = []
        for i in range(4):
            resultant_block[i].append(column_data[0][i] ^ subbed_column_data[i] ^ rcon[i])


        for col in range(1,4):
            for i in range(4):
                resultant_block[i].append(column_data[col][i] ^ resultant_block[i][col-1])

        return resultant_block

    def add_round_key(self, block, round_key):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for col in range(4):
                resultant_block[row].append(block[row][col] ^ round_key[row][col])
        return resultant_block

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
            bin = ""
            for letter in list(str_data):
                bin += self._primeModulusHandler.get_bit_pattern(ord(letter), self.bits_per_letter)
            bin += "0" * (128 - len(bin))
            block = [[],[],[],[]]
            for o in range(0, 128, 32):
                for j in range(0, 32, 8):
                    block[o // 32].append(int(bin[o+j:o+j+8], 2))

            block = self.add_round_key(block, self.key)
            for round in range(9):
                block = self.sub_bytes(block)
                block = self.shift_rows(block)
                block = self.mix_columns(block)
                block = self.add_round_key(block, round_keys[round])

            block = self.sub_bytes(block)
            block = self.shift_rows(block)
            block = self.add_round_key(block, round_keys[9])
            
            for row in range(4):
                for col in range(4):
                    encrypted_data += chr(block[row][col])

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
            bin = ""
            for letter in list(str_data):
                bin += self._primeModulusHandler.get_bit_pattern(ord(letter))
            bin += "0" * (128 - len(bin))
            block = [[],[],[],[]]
            for o in range(0, 128, 32):
                for j in range(0, 32, 8):
                    block[o // 32].append(int(bin[o+j:o+j+8], 2))

            block = self.add_round_key(block, round_keys[9])
            block = self.inverse_shift_rows(block)
            block = self.inverse_sub_bytes(block)
            for round in range(8, -1, -1):
                block = self.add_round_key(block, round_keys[round])
                block = self.inverse_mix_columns(block)
                block = self.inverse_shift_rows(block)
                block = self.inverse_sub_bytes(block)

            block = self.add_round_key(block, self.key)
            
            decrypted_part = ""
            for row in range(4):
                for col in range(4):
                    decrypted_part += self._primeModulusHandler.get_bit_pattern(block[row][col])
            
            for o in range(0, 128, self.bits_per_letter):
                decrypted_data += chr(int(decrypted_part[o:o+self.bits_per_letter], 2))


        return decrypted_data

aes = AesEncryption("aesEncryptionKey", 32)

message = "hello world. How are you doing on this fine evening. Would you like to go somewhere today? I know, lets go to school"

start = datetime.datetime.now()
e_message = aes.encrypt(message)
# d_message = aes.decrypt(e_message)
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
