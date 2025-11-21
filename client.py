import socket, random

aes = __import__("aes-encryption")
rsa = __import__("rsa-encryption")

HEADERSIZE = 5

def format_message(message, header_size):
    bytes_message = str(message).encode(encoding="utf-8")
    return f"{len(bytes_message):<{header_size}}".encode(encoding="utf-8") + bytes_message

class Client:
    def __init__(self, ip, port, bits_per_prime=256):
        self.header_size = 5

        self.generate_rsa_key_pair(bits_per_prime)

        self.connect_socket(ip, port)

    def connect_socket(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.connect((ip, port))

        self.sock.send(format_message(self.pub.e, self.header_size) + format_message(self.pub.n, self.header_size))

        conn_e = int(self.receive_message(False))
        conn_n = int(self.receive_message(False))
        aes_key = self.priv.decrypt(self.receive_message(False))

        self.aesEncryption = aes.AesEncryption(aes_key, 8)
        self.sock_pub = rsa.RsaPublic(conn_e, conn_n)

        received_msg = self.aesEncryption.encrypt("aes key received")
        self.sock.send(format_message(received_msg, self.header_size))

    def generate_rsa_key_pair(self, bits):
        rsaEncryption = rsa.RsaEncryption(8)
        print("Generating keys ... ", end="", flush=True)
        rsaEncryption.generate_keys(bits)
        print("done\n")
        [self.pub, self.priv] = rsaEncryption.generate_classes()

    def receive_message(self, aes_decrypt=True):
        length = self.sock.recv(self.header_size).decode(encoding="utf-8").strip()
        if length == "":
            return False
        length = int(length)

        if aes_decrypt:
            return self.aesEncryption.decrypt(self.sock.recv(length).decode(encoding="utf-8"))
        else:
            return self.sock.recv(length).decode(encoding="utf-8")
    

    def send_message(self, message):
        e_message = self.aesEncryption.encrypt(message)
        self.sock.send(format_message(e_message, self.header_size))

def main():
    client = Client("127.0.0.1", 2801, 512)
    while True:
        message = input("> ")
        client.send_message(message)
        message_from_server = client.receive_message()
        if message_from_server == False:
            print("exiting...")
            break
        else:
            print(message_from_server)
    client.sock.close()

if __name__ == "__main__":
    main()
