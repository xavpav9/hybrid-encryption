import cipher

class VernamCipher(cipher.SymmetricEncryption):
    def __init__(self, key):
        self._key = key
        self._key_binaries = [self.translate_to_binary(letter) for letter in list(key)]

    def translate_to_binary(self, letter):
        decimal = ord(letter)
        binary = ""
        for i in [2**value for value in range(7, -1, -1)]:
            if i <= decimal:
                binary += "1"
                decimal -= i
            else:
                binary += "0"

        return binary

    def xor(self, bit1, bit2):
        if bit1 == bit2:
            return "0"
        else:
            return "1"


    def encrypt(self, message):
        binaries = [self.translate_to_binary(letter) for letter in list(message)]
        new_binaries = []
        return " ".join(binaries)

testCipher = VernamCipher("jdkfa;sjdfks")
print(testCipher.encrypt("hi"))