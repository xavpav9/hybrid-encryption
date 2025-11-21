import random, datetime

from primeModulusHandler import PrimeModulusHandler

class RsaEncryption:
    def __init__(self, encoding=8):
        self._primeModulusHandler = PrimeModulusHandler()
        try:
            if int(encoding) in [8, 16, 24, 32]:
                self.bits_per_letter = int(encoding)
            else:
                raise Exception()
        except:
            raise Exception("Invalid RsaEncryption instantiation - pick a value of bits from 8, 16, 24 or 32.")

    def generate_keys(self, bits_per_key):
        [p, q] = [self._primeModulusHandler.find_prime(bits_per_key), self._primeModulusHandler.find_prime(bits_per_key)]
        n = p * q
        totient = (p - 1) * (q - 1)

        e = 65537
        [d, _, gcd] = self._primeModulusHandler.euclidean_algorithm(e, totient)
        while gcd != 1:
            e = self._primeModulusHandler.find_prime(16)
            [d, _, gcd] = self._primeModulusHandler.euclidean_algorithm(e, totient)

        while d < 0:
            d += totient

        return [n, e, d]

    def encrypt(self, m, n, e):
        encrypted_message = ""
        current_part = ""

        bits_per_packet = self._primeModulusHandler.number_of_bits(n) // self.bits_per_letter * self.bits_per_letter
        encrypted_bits_per_packet = bits_per_packet
        if bits_per_packet != self._primeModulusHandler.number_of_bits(n): encrypted_bits_per_packet = bits_per_packet + self.bits_per_letter
        letters_per_packet = bits_per_packet // self.bits_per_letter

        if letters_per_packet == 0:
            raise Exception("The n is not high enough to encode a single letter.")
        current = 0

        for letter in list(m):
            character_code = ord(letter)
            if current_part != "":
                denary = int(current_part, 2)

            if current == letters_per_packet:
                current_encrypted = self._primeModulusHandler.reduce_exponential_modulo(denary, e, n)
                binary = self._primeModulusHandler.get_bit_pattern(current_encrypted, encrypted_bits_per_packet)

                for i in range(0, len(binary), 8):
                    encrypted_message += chr(int(binary[i:i+8], 2))

                current_part = self._primeModulusHandler.get_bit_pattern(character_code, self.bits_per_letter)
                current = 1
            else:
                current_part += self._primeModulusHandler.get_bit_pattern(character_code, self.bits_per_letter)
                current += 1

        if current != 0:
            current_part += "0" * (letters_per_packet * self.bits_per_letter - len(current_part))
            denary = int(current_part, 2)
            current_encrypted = self._primeModulusHandler.reduce_exponential_modulo(denary, e, n)
            binary = self._primeModulusHandler.get_bit_pattern(current_encrypted, encrypted_bits_per_packet)
            for i in range(0, len(binary), 8):
                encrypted_message += chr(int(binary[i:i+8], 2))

        return encrypted_message

    def decrypt(self, c, n, d):
        decrypted_message = ""

        bits_per_packet = self._primeModulusHandler.number_of_bits(n) // self.bits_per_letter * self.bits_per_letter
        encrypted_bits_per_packet = bits_per_packet
        if bits_per_packet != self._primeModulusHandler.number_of_bits(n): encrypted_bits_per_packet = bits_per_packet + self.bits_per_letter
        letters_per_packet = bits_per_packet // self.bits_per_letter


        if letters_per_packet == 0: raise Exception("The n is not high enough to encode a single letter.")

        for i in range(0, len(c), (encrypted_bits_per_packet) // 8):
            letters = [self._primeModulusHandler.get_bit_pattern(ord(letter)).zfill(8) for letter in list(c[i:i + (encrypted_bits_per_packet) // 8])]
            block = int("".join(letters), 2)
            decrypted_block = self._primeModulusHandler.reduce_exponential_modulo(block, d, n)
            binary = self._primeModulusHandler.get_bit_pattern(decrypted_block, bits_per_packet)
            current_message = ""

            for i in range(0, len(binary), self.bits_per_letter):
                bit_pattern = binary[i:i + self.bits_per_letter]
                denary = int(bit_pattern, 2)
                if denary == 0: break
                current_message += chr(denary)


            decrypted_message += (current_message)

        return "".join(decrypted_message)

rsa = RsaEncryption(24)
p = PrimeModulusHandler()

bits = 32
[n, e, d] = rsa.generate_keys(bits)

message = "“I walked through the treacherous jungle with nothing but a 𝒻ly“"
file = open("heart-of-darkness.txt", "r")
message = file.read()
file.close()

e_message = rsa.encrypt(message, n, e)
print(e_message)
d_message = rsa.decrypt(e_message, n, d)
print(d_message)


"""
file = open("heart-of-darkness.txt", "r")
message = file.read()
file.close()

start = datetime.datetime.now()
print(message)
e_message = rsa.encrypt(message, n, e)
print("e:",e_message)
d_message = rsa.decrypt(e_message, n, d)
print("d:",d_message)
end = datetime.datetime.now()
print(end - start)
"""


"""
message = open("heart-of-darkness.txt", "r").read()
e_message = rsa.encrypt(message, n, e)
d_message = rsa.decrypt(e_message, n, d)
print(e_message)
print(d_message)

file = open("enc-hod.txt", "w")
file.write(e_message)
file.close()

file = open("dec-hod.txt", "w")
file.write(d_message)
file.close()
"""
