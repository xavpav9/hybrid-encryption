class Cipher:
    alphabet = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
    @staticmethod
    def analyse_frequency(text):
        freq_dict = {}
        for letter in Cipher.alphabet:
            freq_dict[letter] = 0

        for letter in text:
            if letter.isalpha():
                freq_dict[letter.lower()] += 1

        return freq_dict

    @staticmethod
    def create_barchart(freq_dict, largest):
        order = sorted(Cipher.alphabet[:], reverse=True, key=lambda letter: freq_dict[letter])
        widths = []

        scale = freq_dict[order[0]] / largest # one scale of freq equals one "0"
        for letter in order:
            widths.append(letter + " " + "0" * int(freq_dict[letter] // scale))
        return widths

class SymmetricEncryption(Cipher):
    @staticmethod
    def basic_encrypt(message, key):
        cipher_text = ""
        key_index = 0
        for letter in list(message):
            cipher_letter = chr(((ord(letter) + ord(key[key_index]) - 32) % 95) + 32)
            cipher_text += cipher_letter
            key_index = (key_index + 1) % len(key)

        return cipher_text

    @staticmethod
    def basic_decrypt(message, key):
        plain_text = ""
        key_index = 0
        for letter in list(message):
            plain_letter = chr((ord(letter) - 32 + 95 - ord(key[key_index])) % 95 + 32)
            plain_text += plain_letter
            key_index = (key_index + 1) % len(key)

        return plain_text
