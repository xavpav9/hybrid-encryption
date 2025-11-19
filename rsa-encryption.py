import random, sys, math

class PrimeModulusHandler:
    def get_bit_pattern(self, denary, zerofill=8):
        highest = 0
        if denary == 0:
            return "0"

        while denary // (2 ** highest) > 1:
            highest += 1

        binary = ""
        for index in range(highest, -1, -1):
            quotient = denary // (2 ** index)
            if quotient == 1:
                binary += "1"
                denary -= quotient * (2 ** index) 
            else:
                binary += "0"

        return binary.zfill(zerofill)

    def get_denary(self, binary):
        return sum([int(binary[len(binary) - i - 1]) * (2 ** i) for i in range(len(binary))])


    def reduce_exponential_modulo(self, base, power, modulus):
        binary = self.get_bit_pattern(power)
        partial_product = 1
        f = base % modulus

        for bit in list(binary[::-1]):
            if bit == "1":
                partial_product = (partial_product * f) % modulus
            f = (f ** 2) % modulus

        return partial_product

    def generate_number(self, bits):
        return random.randint(2**(bits - 1) + 1, 2**(bits) - 1)

    def miller_rabin_test(self, num):
        s = 0
        d = num - 1
        while d % 2 == 0:
            s += 1
            d //= 2

        a = random.randint(2, num - 2)

        if self.reduce_exponential_modulo(a, d, num) == 1: return True # check a^d = 1 (mod n)

        for r in range(s):
            if self.reduce_exponential_modulo(a, 2 ** r * d, num) == num - 1: return True # check a^(2^r*d) = n-1 (mod n)

        return False

    def sieve(self, upper_limit):
        numbers = [True] * (upper_limit + 1)
        for divisor in range(2, int(upper_limit ** 1/2)):
            if numbers[divisor]:
                for non_prime in range(divisor * 2, upper_limit, divisor):
                    numbers[non_prime] = False

        primes = []
        for possible_prime in range(2, upper_limit):
            if numbers[possible_prime]:
                primes.append(possible_prime)

        return primes


    def check_if_prime(self, num):
        primes = self.sieve(1000)
        for prime in primes:
            if num == prime:
                return True
            if num % prime == 0:
                return False


        for i in range(20):
            is_possible_prime = self.miller_rabin_test(num)
            if not is_possible_prime: return False

        return True

    def find_prime(self, bits):
        found = False
        while not found:
            possible_prime = self.generate_number(bits)
            found = self.check_if_prime(possible_prime)
        return possible_prime

    def euclidean_algorithm(self, a, b):
        previous_r = a
        current_r = b
        previous_x = 1
        current_x = 0
        previous_y = 0
        current_y = 1
        current_quotient = 0

        while True:
            next_r = previous_r % current_r
            if next_r == 0:
                break

            next_x = previous_x - current_x * current_quotient
            next_y = previous_y - current_y * current_quotient
            next_quotient = current_r // next_r

            previous_x = current_x
            current_x = next_x
            previous_y = current_y
            current_y = next_y
            previous_r = current_r
            current_r = next_r
            current_quotient = next_quotient

        return [current_x, current_y, current_r] # [x, y, gcd]
            


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

    def encrypt_message(self, m, n, e):
        encrypted_message = ""
        current_part = ""

        bits_per_packet = len(self._primeModulusHandler.get_bit_pattern(n)) // self.bits_per_letter * self.bits_per_letter
        encrypted_bits_per_packet = bits_per_packet
        if bits_per_packet != len(self._primeModulusHandler.get_bit_pattern(n)): encrypted_bits_per_packet = bits_per_packet + self.bits_per_letter
        letters_per_packet = bits_per_packet // self.bits_per_letter

        if letters_per_packet == 0:
            raise Exception("The n is not high enough to encode a single letter.")
        current = 0

        for letter in list(m):
            character_code = ord(letter)
            denary = self._primeModulusHandler.get_denary(current_part)

            if current == letters_per_packet:
                current_encrypted = self._primeModulusHandler.reduce_exponential_modulo(denary, e, n)
                binary = self._primeModulusHandler.get_bit_pattern(current_encrypted, encrypted_bits_per_packet)

                for i in range(0, len(binary), 8):
                    encrypted_message += chr(self._primeModulusHandler.get_denary(binary[i:i+8]))

                current_part = self._primeModulusHandler.get_bit_pattern(character_code, self.bits_per_letter)
                current = 1
            else:
                current_part += self._primeModulusHandler.get_bit_pattern(character_code, self.bits_per_letter)
                current += 1

        if current != 0:
            current_part += "0" * (letters_per_packet * self.bits_per_letter - len(current_part))
            denary = self._primeModulusHandler.get_denary(current_part)
            current_encrypted = self._primeModulusHandler.reduce_exponential_modulo(denary, e, n)
            binary = self._primeModulusHandler.get_bit_pattern(current_encrypted, encrypted_bits_per_packet)
            for i in range(0, len(binary), 8):
                encrypted_message += chr(self._primeModulusHandler.get_denary(binary[i:i+8]))

        return encrypted_message

    def decrypt_message(self, c, n, d):
        decrypted_message = ""

        bits_per_packet = len(self._primeModulusHandler.get_bit_pattern(n)) // self.bits_per_letter * self.bits_per_letter
        encrypted_bits_per_packet = bits_per_packet
        if bits_per_packet != len(self._primeModulusHandler.get_bit_pattern(n)): encrypted_bits_per_packet = bits_per_packet + self.bits_per_letter
        letters_per_packet = bits_per_packet // self.bits_per_letter


        if letters_per_packet == 0: raise Exception("The n is not high enough to encode a single letter.")

        for i in range(0, len(c), (encrypted_bits_per_packet) // 8):
            letters = [self._primeModulusHandler.get_bit_pattern(ord(letter)).zfill(8) for letter in list(c[i:i + (encrypted_bits_per_packet) // 8])]
            block = self._primeModulusHandler.get_denary("".join(letters))
            decrypted_block = self._primeModulusHandler.reduce_exponential_modulo(block, d, n)
            binary = self._primeModulusHandler.get_bit_pattern(decrypted_block, bits_per_packet)
            current_message = ""

            for i in range(0, len(binary), self.bits_per_letter):
                bit_pattern = binary[i:i + self.bits_per_letter]
                denary = self._primeModulusHandler.get_denary(bit_pattern)
                if denary == 0: break
                current_message += chr(denary)


            decrypted_message += (current_message)

        return "".join(decrypted_message)

rsa = RsaEncryption(24)
p = PrimeModulusHandler()

bits = 32
[n, e, d] = rsa.generate_keys(bits)

"""
message = "“I walked through the treacherous jungle with nothing but a 𝒻ly“"
e_message = rsa.encrypt_message(message, n, e)
print(e_message)
d_message = rsa.decrypt_message(e_message, n, d)
print(d_message)

"""

message = open("heart-of-darkness.txt", "r").read()
e_message = rsa.encrypt_message(message, n, e)
d_message = rsa.decrypt_message(e_message, n, d)
print(e_message)
print(d_message)

file = open("enc-hod.txt", "w")
file.write(e_message)
file.close()

file = open("dec-hod.txt", "w")
file.write(d_message)
file.close()
