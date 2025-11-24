import socket, random
from select import select
from primeModulusHandler import PrimeModulusHandler
aes = __import__("aes-encryption")
rsa = __import__("rsa-encryption")

class Server:
    def __init__(self, ip, port, bits_per_prime=256, bits_per_char=8):
        self.header_size = 5

        self.bits_per_char = bits_per_char
        self.generate_rsa_key_pair(bits_per_prime)

        self.initiate_socket(ip, port)

        self._primeModulusHandler = PrimeModulusHandler()

    def generate_aes_key(self):
        key = ""
        for i in range(16):
            key += chr(random.randint(0, 255))

        return key

    def initiate_socket(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.bind((ip, port))
        self.sock.listen(5)

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.conns = [self.sock]
        self.conn_information = {}

    def generate_rsa_key_pair(self, bits_per_prime):
        rsaEncryption = rsa.RsaEncryption(8)
        print("Generating keys ... ", end="", flush=True)
        rsaEncryption.generate_keys(bits_per_prime)
        print("done\n")
        [self.pub, self.priv] = rsaEncryption.generate_classes()

    def accept_connection(self):
        conn, addr = self.sock.accept()
        self.conns.append(conn)
        print(f"\n\nNew connection {conn}, {addr}")
        server_random = self.generate_aes_key()


        client_random = self.receive_message(conn, False)
        conn.send(format_message(self.pub.e, self.header_size))
        conn.send(format_message(self.pub.n, self.header_size))
        conn.send(format_message(self.bits_per_char, self.header_size))
        conn.send(format_message(server_random, self.header_size))
        premaster_secret = self.priv.decrypt(self.receive_message(conn, False))

        aes_key = ""
        for i in range(16):
            aes_key += chr(ord(client_random[i]) ^ ord(server_random[i]) ^ ord(premaster_secret[i]))

        aes_obj = aes.AesEncryption(aes_key, self.bits_per_char)
        self.conn_information[conn] = { "aes": aes_obj, "addr": addr }
        conn.send(format_message(aes_obj.encrypt("finished"), self.header_size))

        confirmation_msg = self.receive_message(conn)
        if confirmation_msg != "finished":
            print(f"-> invalid connection using aes key (in hex): {self._primeModulusHandler.get_hex_from_chars(aes_key)}")
            self.remove_conn(conn)
            return
        else:
            print(f"-> valid connection using aes key (in hex): {self._primeModulusHandler.get_hex_from_chars(aes_key)}")

        username = self.receive_message(conn)
        usernames_in_use = [self.conn_information[other_conn]["username"] for other_conn in self.conn_information if other_conn != conn]
        conn.send(format_message(aes_obj.encrypt("s"), self.header_size))
        if username in usernames_in_use:
            conn.send(format_message(aes_obj.encrypt(f"usernames in use: {','.join(usernames_in_use)}"), self.header_size))
            self.remove_conn(conn)
            print(f"-> invalid username: {username}")
        elif len(username) != len(username.strip()):
            conn.send(format_message(aes_obj.encrypt(f"no trailing or leading spaces in name"), self.header_size))
            self.remove_conn(conn)
            print(f"-> invalid username: {username}")
        elif len(username) < 3:
            conn.send(format_message(aes_obj.encrypt(f"username must be at least 3 characters long"), self.header_size))
            self.remove_conn(conn)
            print(f"-> invalid username: {username}")
        else:
            self.conn_information[conn]["username"] = username
            conn.send(format_message(aes_obj.encrypt(f"connected to server"), self.header_size))
            print(f"-> valid username: {username}")
            self.distribute_message(conn, aes_obj.encrypt(f"{username} has joined"), True)

    def remove_conn(self, conn):
        print(f"\n\nRemoved connection {self.conn_information[conn]['username']} {conn}, {self.conn_information[conn]['addr']}.")
        self.distribute_message(conn, self.conn_information[conn]["aes"].encrypt(f"{self.conn_information[conn]["username"]} has left"), True)

        self.conns.remove(conn)
        self.conn_information.pop(conn)
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()

    def receive_message(self, conn, aes_decrypt=True):
        length = conn.recv(self.header_size).decode(encoding="utf-8").strip()
        if length == "":
            return False
        length = int(length)

        if aes_decrypt:
            return self.conn_information[conn]["aes"].decrypt(conn.recv(length).decode(encoding="utf-8")).strip(chr(0))
        else:
            return conn.recv(length).decode(encoding="utf-8")

    def distribute_message(self, conn, encrypted_message, from_server=False):
        message = self.conn_information[conn]["aes"].decrypt(encrypted_message)
        if not from_server:
            username = self.conn_information[conn]["username"]
            print(f"\n\nNew message from {self.conn_information[conn]['username']} ({conn})")
            print(f"-> Original encrypted message (in hex): {self._primeModulusHandler.get_hex_from_chars(encrypted_message)}")
            print(f"-> Decrypted message (in chars): {message}")
        else:
            username = "s"

        for other_conn in self.conns:
            if other_conn != conn and other_conn != self.sock:
                e_message = self.conn_information[other_conn]["aes"].encrypt(message)
                e_username = self.conn_information[other_conn]["aes"].encrypt(username)
                other_conn.send(format_message(e_username, self.header_size) + format_message(e_message, self.header_size))
                if not from_server:
                    print(f"To {self.conn_information[other_conn]['username']} ({other_conn})")
                    print(f"-> New encrypted message (in hex): {self._primeModulusHandler.get_hex_from_chars(e_message)}")

def format_message(message, header_size):
    bytes_message = str(message).encode(encoding="utf-8")
    return f"{len(bytes_message):<{header_size}}".encode(encoding="utf-8") + bytes_message

server = Server("0.0.0.0", 2801, 1024, 32)
while True:
    conns_to_read, _, conns_in_error = select(server.conns,server. conns,server. conns)

    for conn in conns_in_error:
        server.remove_conn(conn)

    for conn in conns_to_read:
        if conn == server.sock:
            server.accept_connection()
        else:
            message = server.receive_message(conn, False)
            if message == False:
                server.remove_conn(conn)
            else:
                server.distribute_message(conn, message)
