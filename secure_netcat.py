from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import socket
import argparse
import select
import time
import sys
import pickle


# Used to construct the application layer datagram
class Message:
    def __init__(self, nonce, salt, ciphertext, digest):
        self.digest = digest
        self.salt = salt
        self.nonce = nonce
        self.ciphertext = ciphertext

    def encode(self):
        try:
            return pickle.dumps(self, -1)
        except pickle.PicklingError:
            handle_error("Could not encode the object")

    @staticmethod
    def decode(encoded_msg):
        try:
            return pickle.loads(encoded_msg)
        except pickle.UnpicklingError:
            handle_error("Could not decode the object")


def handle_error(message):
    sys.stderr.write(message)
    exit(1)


def validate_port(args_port):
    port = int(args_port)
    if not 1024 < port < 65535:
        handle_error("Port value should be an integer within range 1024-65535")
    else:
        return port


# Open a connection to server at 'hostname' and 'port'
def connect_to_server(hostname, port):
    socket.setdefaulttimeout(60)

    # Open a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (hostname, port)
    try:
        s.connect(server_address)
    except socket.error as err:
        handle_error("connect_to_server (%s, %s) failed due to %s" % (hostname, port, err))
    return s


# Listen at the given server address
def listen_for_clients(server_address):
    # Open a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    timeout = 60
    while timeout > 0:
        try:
            s.bind(server_address)
            s.listen(1)
            break
        except socket.error as _:
            time.sleep(5)
            timeout -= 5
    if timeout <= 0:
        handle_error("Could not bind to %s within %d seconds. Server could not be started." % (str(server_address), 60))
    else:
        return s


def get_cipher(password, nonce, salt):
    # Construct a PBKDF2 key for the cipher
    key = PBKDF2(password, salt, dkLen=32, count=1000)
    # AES encryption in GCM mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher


# Encrypt a plaintext using given key with AES-256
def encrypt_data(key, plaintext):
    nonce = get_random_bytes(16)
    salt = get_random_bytes(16)
    cipher = get_cipher(key, nonce, salt)
    ciphertext, digest = cipher.encrypt_and_digest(plaintext)
    # Send the salt and nonce as well to the receiver for decryption
    return Message(nonce, salt, ciphertext, digest)


# Decrypt the data using given key with AES-256
def decrypt_data(data, key):
    msg = Message.decode(data)
    cipher = get_cipher(key, msg.nonce, msg.salt)
    try:
        plaintext = cipher.decrypt_and_verify(msg.ciphertext, msg.digest)
        return plaintext
    except ValueError as e:
        # Exit with an error if the MAC check failed
        handle_error("Packet lacks integrity! %s" % e)


# Client flow
def client(key, hostname, port):
    try:
        sock = connect_to_server(hostname, port)
        sockets = [sys.stdin, sock]
        try:
            while True:
                for conn in select.select(sockets, [], [], 0)[0]:
                    # Read from STDIN and send the data to server
                    if conn is sys.stdin:
                        line = sys.stdin.readline()
                        if line:
                            msg = encrypt_data(key, line)
                            sock.sendall(msg.encode())
                        else:
                            exit(0)
                    # Read from socket
                    else:
                        data = conn.recv(1024)
                        plaintext = decrypt_data(data, key)
                        sys.stdout.write(plaintext)
        # Handle keyboard interrupt (CTRL+c)
        except KeyboardInterrupt:
            sock.close()
            exit(0)
    except Exception as e:
        handle_error("Exception while sending. %s" % e)


# Server flow
def server(key, listen):
    try:
        sock = listen_for_clients(("localhost", listen))
        sockets = [sys.stdin, sock]
        try:
            while True:
                for conn in select.select(sockets, [], [], 0)[0]:
                    try:
                        # new connection request received
                        if conn is sock:
                            connection, client_address = conn.accept()
                            sockets.append(connection)
                        # STDIN is the source of input
                        elif conn is sys.stdin:
                            for s in sockets:
                                if s not in [sys.stdin, sock]:
                                    line = conn.readline()
                                    msg = encrypt_data(key, line)
                                    s.sendall(msg.encode())
                        # socket is the source of input
                        else:
                            data = conn.recv(1024)
                            if not data:
                                sockets.remove(conn)
                                exit(0)
                            else:
                                plaintext = decrypt_data(data, key)
                                sys.stdout.write(plaintext)
                    except socket.error as err:
                        handle_error("Could not accept connection due to error : %s" % err)
        # Handle keyboard interrupt (CTRL+c)
        except KeyboardInterrupt:
            sock.close()
            exit(0)
    except Exception as e:
        handle_error("Exception while receiving. %s" % e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="Key", type=str, required=True)
    parser.add_argument("-l", "--listen", help="Port number", type=int, required=False)
    parser.add_argument("destination", nargs='?')
    parser.add_argument("port", nargs='?')
    args = parser.parse_args()

    if args.key and args.listen and not args.destination and not args.port:
        server(args.key, args.listen)
    elif args.key and args.destination and args.port and not args.listen:
        port = validate_port(args.port)
        client(args.key, args.destination, port)
    else:
        handle_error("Exiting due to incorrect usage of arguments.\n Usage : snc [-l] [--key KEY] [destination] [port]")


if __name__ == "__main__":
    main()
