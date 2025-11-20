import random

class PrimeModulusHandler:
    def get_bit_pattern(self, denary, zerofill=8):
        highest = 0
        if denary == 0:
            return "0".zfill(zerofill)

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

    def euclidean_algorithm(self, a, b): # extended
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

    def xor(self, num1, num2):
        bin1 = self.get_bit_pattern(num1, 0)
        bin2 = self.get_bit_pattern(num2, len(bin1))
        bin1 = bin1.zfill(len(bin2))
        resultant_bin = ""

        for i in range(len(bin1)):
            if bin1[i] == bin2[i]: resultant_bin += "0"
            else: resultant_bin += "1"

        return self.get_denary(resultant_bin)

    def multiply_in_gf8(self, num1, num2): # in GF(2^8)
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
                    resultant_den = self.xor(resultant_den, reducer)

            else:
                resultant_den = self.xor(resultant_den, num1)

        return resultant_den

    def multiplicative_inverse_in_gf8(self, num):
        if num == 0:
            return 0
        for possible_inverse in range(1, 256):
            if self.multiply_in_gf8(num, possible_inverse) == 1:
                return possible_inverse

    def affine_transformation(self, A, num, b):
        bin = self.get_bit_pattern(num)[::-1]
        resultant_bit_pattern = ""
        for row in A:
            resultant_bit = 0
            for i in range(8):
                if row[i] == 1:
                    resultant_bit = self.xor(resultant_bit, int(bin[i]))
            resultant_bit_pattern += str(resultant_bit)
        resultant_num = self.get_denary(resultant_bit_pattern)

        return self.get_bit_pattern(self.xor(resultant_num, self.get_denary(b)))[::-1]
