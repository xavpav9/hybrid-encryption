import cipher


class CaeserCipher(cipher.Cipher):
    def __init__(self, key):
        self._key = key

    def encrypt(self, message):
        new_message = ""
        while self._key < 0:
            self._key += 26
        self._key = self._key % 26

        for letter in list(message):
            if letter.isalpha():
                lower = 65
                if letter.islower():
                    lower = 97

                new_message += chr((ord(letter) % lower + self._key) % 26 + lower)
            else:
                new_message += letter

        return new_message

key4 = CaeserCipher(2601)
print(key4.encrypt("aAzZ"))
text = open("heart-of-darkness.txt", "r", encoding="UTF-8").read()
for str in CaeserCipher.create_barchart(CaeserCipher.analyse_frequency(text), 50):
    print(str)
