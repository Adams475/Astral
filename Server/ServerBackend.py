import socket
import threading
import tkinter as tk

import Astral.utils


class ServerInstance:

    def __init__(self):
        self.clients = []
        self.should_listen = False
        self.threads = []
        # Lazy default for debugging
        self.port = '8080'
        self.text_frame = None
        self.rsa_private_key_enc_dec = ""
        self.rsa_private_key_signing = ""

    def decrypt_keys(self, password):
        encrypted_rsa_key_file_enc_dec = "server/encrypted_server_enc_dec_pub_prv.txt"
        encrypted_rsa_key_file_signing = "server/encrypted_server_signing_verification_pub_prv.txt"
        try:
            self.rsa_private_key_enc_dec = Astral.utils.decrypt_rsa_private_key(encrypted_rsa_key_file_enc_dec, password)
            self.rsa_private_key_signing = Astral.utils.decrypt_rsa_private_key(encrypted_rsa_key_file_signing, password)
            self.write_text("Keys Decrypted Successfully")
        except Exception as e:
            self.write_text("Incorrect Password")

    def listen(self, port):
        # TODO - Check if signed in
        if not Astral.utils.debug:
            self.port = port
        thread = threading.Thread(target=self.spawn_servers)
        thread.start()
        print("returning")

    def spawn_servers(self):
        self.should_listen = True
        server_socket = socket.socket()
        server_name = "127.0.0.1"

        server_socket.bind((server_name, int(self.port)))
        server_socket.listen(3)
        print("listening")

        while self.should_listen:
            connection, addr = server_socket.accept()
            thread = threading.Thread(target=self.handle_client, args=(connection, addr))
            self.threads.append(thread)
            thread.start()

    def handle_client(self, connection, addr):
        while True:
            # NOTE - Currently, assuming this data decodes to a string
            data = connection.recv(8192)
            # TODO find out proper way for finding out if client wants to close connection
            if data.decode() == "closing session...":
                break
            self.write_text(data.decode())
        connection.close()

    def write_text(self, text):
        self.text_frame.insert(tk.INSERT, text + "\n")
        self.text_frame.see(tk.END)

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame
