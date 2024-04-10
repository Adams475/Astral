import socket
import tkinter as tk
import utils

from Crypto.Hash import SHA256


class ClientInstance:

    def __init__(self, public_enc, public_sig):
        self.public_enc = public_enc
        self.public_sig = public_sig
        # Lazy defaults for debugging
        self.server_ip = "127.0.0.1"
        self.server_port = "8080"
        self.name = "q"
        self.password = "Obscurity"
        self.password_hash = None
        self.connection = None
        self.text_frame = None

    def login(self, server_ip, server_port, name, password):
        if not utils.debug:
            self.server_ip = server_ip
            self.server_port = server_port
            self.name = name
            self.password = password

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((server_ip, int(server_port)))
            self.connection = sock

        except Exception as e:
            print("connection failure: ", e)

    def enroll(self, server_ip, server_port, name, password):
        if not utils.debug:
            self.server_ip = server_ip
            self.server_port = server_port
            self.name = name
            self.password = password

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, int(self.server_port)))
            self.connection = sock
            self.secure_enroll()
        except Exception as e:
            print("connection failure: ", e)

    def secure_enroll(self):
        self.password_hash = SHA256.new(self.password.encode()).digest()
        # Concatenate the most significant half of the hash with the username

        # ???
        concatenated_message = self.password_hash[:len(self.password_hash) // 2] + self.name.encode()

        # Encrypt the concatenated message using the RSA public key of the server
        encrypted_message = utils.encrypt_message(concatenated_message, self.public_enc)
        self.send_data(encrypted_message)

    def send_data(self, data):
        print("sending:", data)
        self.write_text(data)
        self.connection.send(data)

    def send_string(self, message):
        if self.connection is None:
            self.write_text("Not connected to server! Failed to send message.")
            return
        self.connection.send(bytes(message, 'utf-8'))

    def write_text(self, text):
        self.text_frame.insert(tk.INSERT, text.__str__() + "\n")
        self.text_frame.see(tk.END)

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame

    def listen(self, sock):
        while True:
            # NOTE - Currently, assuming this data decodes to a string
            data = sock.recv(8192)
            # TODO find out proper way for finding out if client wants to close connection
            if data.decode() == "closing session...":
                break
            self.write_text(data.decode())
        sock.close()
