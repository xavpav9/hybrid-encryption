import socket, random, readline, os, sys
from threading import Thread
from primeModulusHandler import PrimeModulusHandler

clear_message = "clear"
if os.name == "posix": clear_message = "cls"

aes = __import__("aes-encryption")
rsa = __import__("rsa-encryption")

HEADERSIZE = 5

def format_message(message, header_size):
    bytes_message = str(message).encode(encoding="utf-8")
    return f"{len(bytes_message):<{header_size}}".encode(encoding="utf-8") + bytes_message

class Client:
    def __init__(self, ip, port, username):
        self.header_size = 5
        self.username = username

        self.connect_socket(ip, port)

    def generate_aes_key(self):
        key = ""
        for i in range(16):
            key += chr(random.randint(0, 255))

        return key

    def connect_socket(self, ip, port):
        print("Connecting to socket ... ", end="", flush=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.connect((ip, port))

        client_random = self.generate_aes_key()
        self.sock.send(format_message(client_random, self.header_size))

        conn_e = int(self.receive_message(False))
        conn_n = int(self.receive_message(False))
        bits_per_char = int(self.receive_message(False))
        server_random = self.receive_message(False)

        premaster_secret = self.generate_aes_key()

        aes_key = ""
        for i in range(16):
            aes_key += chr(ord(client_random[i]) ^ ord(server_random[i]) ^ ord(premaster_secret[i]))

        self.aesEncryption = aes.AesEncryption(aes_key, bits_per_char)
        self.sock_pub = rsa.RsaPublic(conn_n, conn_e, 8)


        self.sock.send(format_message(self.sock_pub.encrypt(premaster_secret), self.header_size))

        self.send_message("finished")
        self.send_message(self.username)

        confirmation_msg = self.receive_message()
        if confirmation_msg != "finished":
            print("invalid connection\n")
            self.sock.close()
            sys.exit()
        
        print("done\n")

    def receive_message(self, aes_decrypt=True):
        length = self.sock.recv(self.header_size).decode(encoding="utf-8").strip()
        if length == "":
            return False
        length = int(length)

        if aes_decrypt:
            return self.aesEncryption.decrypt(self.sock.recv(length).decode(encoding="utf-8")).strip(chr(0))
        else:
            return self.sock.recv(length).decode(encoding="utf-8")
    

    def send_message(self, message):
        e_message = self.aesEncryption.encrypt(message)
        self.sock.send(format_message(e_message, self.header_size))

def main(client, messages):
    while True:
        try:
            message = input(f"\n{client.username}> ")
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
            print(f"\n{client.username}> " + current_line, end="", flush=True)

def reprint_screen(messages):
    os.system(clear_message)
    for message_data in messages:
        print(f"{message_data['username']}> {message_data['message']}")

if __name__ == "__main__":
    messages = []
    username = input("Enter username: ")
    client = Client("127.0.0.1", 2801, username)
    t1 = Thread(target=output_messages, args=[client, messages,])
    t1.start()
    main(client, messages)
    try:
        t1.join()
    except:
        pass
    client.sock.close()
