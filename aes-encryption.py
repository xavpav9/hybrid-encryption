from primeModulusHandler import PrimeModulusHandler

class AesEncryption:
    def __init__(self):
         self._primeModulusHandler= PrimeModulusHandler()

    def mix_columns(self, block):
        matrix = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
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

    def shift_rows(self, block):
        resultant_block = [[],[],[],[]]
        for row in range(4):
            for i in range(4):
                resultant_block[row].append(block[row][(i + row) % 4])
        return resultant_block

aes = AesEncryption()

# tests:
# block = [[212, 224, 184, 30], [191, 180, 65, 39], [93, 82, 17, 152], [48, 174, 241, 229]]
# print(aes.mix_columns(block))
# print(aes.shift_rows(block))
