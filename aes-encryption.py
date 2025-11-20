from primeModulusHandler import PrimeModulusHandler

class AesEncryption:
    def __init__(self):
        self._primeModulusHandler= PrimeModulusHandler()
        self.rcon = [1,2,4,8,16,32,64,128,27,54]

    def rijndael_sbox(self, num):
        if num == 0: return 99 # special case
        A = [[1,0,0,0,1,1,1,1],[1,1,0,0,0,1,1,1],[1,1,1,0,0,0,1,1],[1,1,1,1,0,0,0,1],[1,1,1,1,1,0,0,0],[0,1,1,1,1,1,0,0],[0,0,1,1,1,1,1,0],[0,0,0,1,1,1,1,1]]
        b = "11000110"
        inv_num = self._primeModulusHandler.multiplicative_inverse_in_gf8(num)
        return self._primeModulusHandler.get_denary(self._primeModulusHandler.affine_transformation(A, inv_num, b))

    def rijndael_inverse_sbox(self, num):
        if num == 99: return 0 # special case
        A = [[0,0,1,0,0,1,0,1],[1,0,0,1,0,0,1,0],[0,1,0,0,1,0,0,1],[1,0,1,0,0,1,0,0],[0,1,0,1,0,0,1,0],[0,0,1,0,1,0,0,1],[1,0,0,1,0,1,0,0],[0,1,0,0,1,0,1,0]]
        b = "10100000"
        inv_num = self._primeModulusHandler.get_denary(self._primeModulusHandler.affine_transformation(A, num, b))
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
                    result = self._primeModulusHandler.xor(result, data)

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
                resultant_block[row].append(self.rijndael_sbox(block[row][i]))
        return resultant_block

    def inverse_sub_bytes(self, block):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for i in range(4):
                resultant_block[row].append(self.rijndael_inverse_sbox(block[row][i]))
        return resultant_block

    def next_key(self, block, rcon):
        resultant_block = [[],[],[],[]]
        column_data = []
        for i in range(4):
            column_data.append([row[i] for row in block])

        subbed_column_data = []
        for i in range(4):
            subbed_column_data.append(self.rijndael_sbox(column_data[3][(i + 1) % 4]))

        first_col = []
        for i in range(4):
            resultant_block[i].append(self._primeModulusHandler.xor(self._primeModulusHandler.xor(column_data[0][i], subbed_column_data[i]), rcon[i]))


        for col in range(1,4):
            for i in range(4):
                resultant_block[i].append(self._primeModulusHandler.xor(column_data[col][i], resultant_block[i][col-1]))

        return resultant_block



"""tests:
aes = AesEncryption()

b1 = [[43,40,171,9],[126,174,247,207],[21,210,21,79],[22,166,136,60]]

for i in range(10):
    b1 = aes.next_key(b1, [aes.rcon[i], 0, 0, 0])

print(b1)
"""
