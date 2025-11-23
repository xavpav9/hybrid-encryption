import socket, random, readline, os
from threading import Thread

aes = __import__("aes-encryption")
rsa = __import__("rsa-encryption")

HEADERSIZE = 5

def format_message(message, header_size):
    bytes_message = str(message).encode(encoding="utf-8")
    return f"{len(bytes_message):<{header_size}}".encode(encoding="utf-8") + bytes_message

class Client:
    def __init__(self, ip, port, username, bits_per_prime=256):
        self.header_size = 5
        self.username = username

        self.generate_rsa_key_pair(bits_per_prime)

        self.connect_socket(ip, port)

    def connect_socket(self, ip, port):
        print("Connecting to socket ... ", end="", flush=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.connect((ip, port))

        self.sock.send(format_message(self.pub.e, self.header_size) + format_message(self.pub.n, self.header_size))

        conn_e = int(self.receive_message(False))
        conn_n = int(self.receive_message(False))
        bits_per_char = int(self.receive_message(False))
        aes_key = self.priv.decrypt(self.receive_message(False))

        self.aesEncryption = aes.AesEncryption(aes_key, bits_per_char)
        self.sock_pub = rsa.RsaPublic(conn_e, conn_n)

        self.send_message("aes key received")
        self.send_message(self.username)
        print("done\n")

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

def main(client, messages):
    while True:
        try:
            message = input("\n> ")
        except:
            print("Disconnected. You might need to press <C-c> to quit.")
            break
        messages.append({"username": client.username, "message": message})
        reprint_screen(messages)
        client.send_message(message)
    client.sock.close()

def output_messages(client, messages):
    while True:
        other_username = client.receive_message()
        if other_username == False:
            print("Disconnected from server")
            break

        other_message = client.receive_message()
        if other_message == False:
            print("Disconnected from server")
            break
        else:
            messages.append({"username": other_username, "message": other_message})
            current_line = readline.get_line_buffer()
            reprint_screen(messages)
            print("\n> " + current_line, end="", flush=True)

def reprint_screen(messages):
    os.system("clear")
    for message_data in messages:
        print(f"{message_data['username']}> {message_data['message']}")

if __name__ == "__main__":
    messages = []
    username = input("Enter username: ")
    client = Client("127.0.0.1", 2801, username, 512)
    t1 = Thread(target=output_messages, args=[client, messages,])
    t1.start()
    main(client, messages)
    try:
        t1.join()
    except:
        pass
    client.sock.close()
