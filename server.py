import socket, random
from select import select
aes = __import__("aes-encryption")
rsa = __import__("rsa-encryption")

class Server:
    def __init__(self, ip, port, bits_per_prime=256, bits_per_char=8):
        self.header_size = 5

        self.bits_per_char = bits_per_char
        self.generate_rsa_key_pair(bits_per_prime)

        self.initiate_socket(ip, port)

    def initiate_socket(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.bind((ip, port))
        self.sock.listen(5)

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.conns = [self.sock]
        self.conn_information = {}

    def generate_rsa_key_pair(self, bits_per_prime):
        rsaEncryption = rsa.RsaEncryption(self.bits_per_char)
        print("Generating keys ... ", end="", flush=True)
        rsaEncryption.generate_keys(bits_per_prime)
        print("done\n")
        [self.pub, self.priv] = rsaEncryption.generate_classes()

    def generate_aes_key(self):
        key = ""
        for i in range(16):
            key += chr(random.randint(0, 255))

        return key

    def accept_connection(self):
        conn, addr = self.sock.accept()
        self.conns.append(conn)
        print(conn, addr)

        conn_e = int(self.receive_message(conn, False))
        conn_n = int(self.receive_message(conn, False))
        aes_key = self.generate_aes_key()

        aes_obj = aes.AesEncryption(aes_key, self.bits_per_char)
        rsa_obj = rsa.RsaPublic(conn_n, conn_e, 8)
        self.conn_information[conn] = {"rsa": rsa_obj,
                                       "aes": aes_obj }

        conn.send(format_message(self.pub.e, self.header_size) + format_message(self.pub.n, self.header_size) + format_message(self.bits_per_char, self.header_size))
        conn.send(format_message(rsa_obj.encrypt(aes_key), self.header_size))

        valid_received_msg = "aes key received"
        received_msg = self.receive_message(conn)
        print(received_msg)
        if received_msg != valid_received_msg:
            self.remove_conn(conn)
        else:
            print("valid")
            
    def remove_conn(self, conn):
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        self.conns.remove(conn)
        self.conn_information.pop(conn)

    def receive_message(self, conn, aes_decrypt=True):
        length = conn.recv(self.header_size).decode(encoding="utf-8").strip()
        if length == "":
            return False
        length = int(length)

        if aes_decrypt:
            return self.conn_information[conn]["aes"].decrypt(conn.recv(length).decode(encoding="utf-8"))
        else:
            return conn.recv(length).decode(encoding="utf-8")

    def distribute_message(self, conn, message):
        print(f"\nNew message from {conn}: ({message})")
        for other_conn in self.conns:
            if other_conn != conn and other_conn != self.sock:
                e_message = self.conn_information[other_conn]["aes"].encrypt(message)
                other_conn.send(format_message(e_message, self.header_size))
                print(f"To {other_conn}: {e_message}")

def format_message(message, header_size):
    bytes_message = str(message).encode(encoding="utf-8")
    return f"{len(bytes_message):<{header_size}}".encode(encoding="utf-8") + bytes_message

server = Server("0.0.0.0", 2801, 1024, 8)
while True:
    conns_to_read, _, conns_in_error = select(server.conns,server. conns,server. conns)
    for conn in conns_in_error:
        server.remove_conn(conn)

    for conn in conns_to_read:
        if conn == server.sock:
            server.accept_connection()
        else:
            message = server.receive_message(conn)
            if not message:
                server.remove_conn(conn)
            else:
                server.distribute_message(conn, message)
