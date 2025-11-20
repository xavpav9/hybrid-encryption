from primeModulusHandler import PrimeModulusHandler

p = PrimeModulusHandler()
def xor(num1, num2):
    bin1 = p.get_bit_pattern(num1, 0)
    bin2 = p.get_bit_pattern(num2, len(bin1))
    bin1 = bin1.zfill(len(bin2))
    resultant_bin = ""

    for i in range(len(bin1)):
        if bin1[i] == bin2[i]: resultant_bin += "0"
        else: resultant_bin += "1"

    print(bin1)
    print(bin2)
    return p.get_denary(resultant_bin)

def multiply(num1, num2): # in GF(2^8)
    reducer = 283 # #11b
    resultant_den = num1

    order = []
    while num2 != 1:
        if num2 % 2 == 0:
            order.append(1)
            num2 //= 2
        else:
            order.append(0)
            num2 -= 1

    order = order[::-1]
    for operation in order:
        if operation == 1:
            resultant_den *= 2
            if resultant_den > 255:
                resultant_den = xor(resultant_den, reducer)

        else:
            resultant_den = xor(resultant_den, num1)

    return resultant_den

def mix_columns(block):
    matrix = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    resultant_block = [[],[],[],[]]
    for column_number in range(4):
        column_data = [row[column_number] for row in block]
        for row_number in range(4):
            matrix_data = matrix[row_number]
            values_to_be_summed = [multiply(column_data[i], matrix_data[i]) for i in range(4)]
            result = 0
            for data in values_to_be_summed:
                result = xor(result, data)

            resultant_block[row_number].append(result)

    return resultant_block



# print(xor(820148930, 60327))
# print(multiply(191, 3))
print(mix_columns([[212, 224, 184, 30], [191, 180, 65, 39], [93, 82, 17, 152], [48, 174, 241, 229]]))
