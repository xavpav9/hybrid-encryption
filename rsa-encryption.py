from primeModulusHandler import PrimeModulusHandler

class RsaEncryption:
    def __init__(self, encoding=8):
        self._primeModulusHandler = PrimeModulusHandler()
        [self.n, self.e, self.d] = self.generate_keys(8) # placeholder keys
        try:
            if int(encoding) in [8, 16, 24, 32]:
                self.bits_per_letter = int(encoding)
            else:
                raise Exception()
        except:
            raise Exception("Invalid RsaEncryption instantiation - pick a value of bits from 8, 16, 24 or 32.")

    def generate_keys(self, bits_per_prime):
        [p, q] = [self._primeModulusHandler.find_prime(bits_per_prime), self._primeModulusHandler.find_prime(bits_per_prime)]
        n = p * q
        totient = (p - 1) * (q - 1)

        e = 65537
        [d, _, gcd] = self._primeModulusHandler.extended_euclidean_algorithm(e, totient)
        while gcd != 1:
            e = self._primeModulusHandler.find_prime(16)
            [d, _, gcd] = self._primeModulusHandler.extended_euclidean_algorithm(e, totient)

        while d < 0:
            d += totient

        [self.n, self.e, self.d] = [n, e, d]
        return [n, e, d]

    def generate_classes(self):
        return [ RsaPublic(self.n, self.e, self.bits_per_letter), RsaPrivate(self.n, self.d, self.bits_per_letter) ]

    def encrypt(self, m, n, e):
        encrypted_message = ""
        current_part = ""

        bits_per_packet = self._primeModulusHandler.number_of_bits(n) // self.bits_per_letter * self.bits_per_letter
        if bits_per_packet == self._primeModulusHandler.number_of_bits(n): bits_per_packet -= self.bits_per_letter
        encrypted_bits_per_packet = bits_per_packet
        if bits_per_packet != self._primeModulusHandler.number_of_bits(n): encrypted_bits_per_packet = bits_per_packet + self.bits_per_letter
        letters_per_packet = bits_per_packet // self.bits_per_letter

        if letters_per_packet == 0:
            raise Exception("The n is not high enough to encode a single letter.")
        current = 0

        for letter in list(m):
            character_code = ord(letter)

            if current == letters_per_packet:
                denary = int(current_part, 2)
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
        if bits_per_packet == self._primeModulusHandler.number_of_bits(n): bits_per_packet -= self.bits_per_letter
        encrypted_bits_per_packet = bits_per_packet
        if bits_per_packet != self._primeModulusHandler.number_of_bits(n): encrypted_bits_per_packet = bits_per_packet + self.bits_per_letter
        letters_per_packet = bits_per_packet // self.bits_per_letter


        if letters_per_packet == 0: raise Exception("The n is not high enough to encode a single letter.")

        for i in range(0, len(c), (encrypted_bits_per_packet) // 8):
            letters = [self._primeModulusHandler.get_bit_pattern(ord(letter)) for letter in list(c[i:i + (encrypted_bits_per_packet) // 8])]
            block = int("".join(letters), 2)
            decrypted_block = self._primeModulusHandler.reduce_exponential_modulo(block, d, n)
            binary = self._primeModulusHandler.get_bit_pattern(decrypted_block, bits_per_packet)
            current_message = ""

            for i in range(0, len(binary), self.bits_per_letter):
                bit_pattern = binary[i:i + self.bits_per_letter]
                denary = int(bit_pattern, 2)
                current_message += chr(denary)


            decrypted_message += (current_message)

        return "".join(decrypted_message)

class RsaPublic(RsaEncryption):
    def __init__(self, n, e, encoding=8):
        super().__init__(encoding)
        self.n = n
        self.e = e
        self.d = None

    def encrypt(self, message):
        return super().encrypt(message, self.n, self.e)

    def decrypt(self, message):
        return super().decrypt(message, self.n, self.e)

class RsaPrivate(RsaEncryption):
    def __init__(self, n, d, encoding=8):
        super().__init__(encoding)
        self.n = n
        self.e = None
        self.d = d

    def encrypt(self, message):
        return super().encrypt(message, self.n, self.d)

    def decrypt(self, message):
        return super().decrypt(message, self.n, self.d)



if __name__ == "__main__":
    rsa = RsaEncryption(8)

    bits = 1024
    print("Generating keys ... ", end="", flush=True)
    rsa.generate_keys(bits)
    print("done\n")
    [pub, priv] = rsa.generate_classes()

    message = "heLlo world."
    print(message)
    e_message = pub.encrypt(message)
    print("e:", e_message)
    d_message = priv.decrypt(e_message)
    print("d:", d_message)


    print()
    message = "Bye, world!"
    print(message)
    e_message = priv.encrypt(message)
    print("e:", e_message)
    d_message = pub.decrypt(e_message)
    print("d:", d_message)
