import json
import socket
import threading
import tkinter as tk

import utils

PASSWORD_HASH_LEN = 16  # Magic Number, the password hash sent by the client is 16 bytes long
REQUEST_HEADERS = {'0'.encode(): "RSA", '1'.encode(): "CLEAR-TEXT", '2'.encode(): "AES"}


class ServerInstance:

    def __init__(self):
        self.client_passwords = {}
        self.hmac_randoms = {}
        self.should_listen = False
        self.threads = []
        # Lazy default for debugging
        if utils.debug:
            self.port = '8080'
        else:
            self.port = None
        self.text_frame = None
        self.rsa_private_key_enc_dec = ""
        self.rsa_private_key_signing = ""
        self.authenticated = False

    def decrypt_keys(self, password):
        encrypted_rsa_key_file_enc_dec = "server/encrypted_server_enc_dec_pub_prv.txt"
        encrypted_rsa_key_file_signing = "server/encrypted_server_signing_verification_pub_prv.txt"
        try:
            self.rsa_private_key_enc_dec = utils.decrypt_rsa_private_key(encrypted_rsa_key_file_enc_dec,
                                                                         password)
            self.rsa_private_key_signing = utils.decrypt_rsa_private_key(encrypted_rsa_key_file_signing,
                                                                         password)
            self.write_text("Keys Decrypted Successfully")
            self.authenticated = True
        except Exception as e:
            self.write_text("Incorrect Password")

    def listen(self, port):
        # TODO - Check if signed in
        if not utils.debug:
            self.port = port
        thread = threading.Thread(target=self.spawn_servers)
        thread.start()
        print("returning")

    def spawn_servers(self):
        if not self.authenticated:
            self.write_text("You must login before starting the server")
            return

        self.should_listen = True
        server_socket = socket.socket()
        server_name = "127.0.0.1"

        server_socket.bind((server_name, int(self.port)))
        server_socket.listen(3)
        self.write_text(f"Listening on port: {self.port}")

        while self.should_listen:
            connection, addr = server_socket.accept()
            thread = threading.Thread(target=self.handle_client, args=(connection, addr))
            self.threads.append(thread)
            thread.start()

    def handle_client(self, connection, addr):
        print("Thread")
        self.write_text(f"Connection request from address: {addr}")
        response = ""
        while True:
            # NOTE - Currently, assuming this data decodes to a string
            data = connection.recv(8192)
            # TODO find out proper way for finding out if client wants to close connection
            client_message = self.parse_raw_data(data)
            if client_message is None:
                continue

            self.write_text(f"Message from address {addr}: {client_message}")
            response, keep_alive = self.handle_request(client_message)
            if response is not None:
                self.write_text(f"Response to address {addr}: {response}")
                connection.send(response)
            if not keep_alive:
                break
        connection.close()

    def write_text(self, text):
        self.text_frame.insert(tk.INSERT, text + "\n")
        self.text_frame.see(tk.END)

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame

    # First byte of all client messages indicate the cryptography used. See post 49
    # Takes first byte and decrypts
    def parse_raw_data(self, data):
        header_byte = data[:1]
        raw_data = data[1:]
        if REQUEST_HEADERS[header_byte] == "RSA":
            return utils.decrypt_message(raw_data, self.rsa_private_key_enc_dec)
        elif REQUEST_HEADERS[header_byte] == "CLEAR-TEXT":
            return raw_data
        elif REQUEST_HEADERS[header_byte] == "AES":
            # TODO
            return None
        else:
            # Exception
            return None

    # Parse verb and message body
    def handle_request(self, message):
        data = json.loads(message)
        verb = data['Verb']
        body = data['Body']  # I use body for the signature, no real reason why
        hash_msg = utils.hash_message(body.encode('latin-1'))
        signed_msg = self.sign_message(hash_msg).decode('latin-1')
        if verb == 'Enroll':
            if self.enroll_user(body):
                response = json.dumps({"Status": "Success", "Signature": signed_msg})
                return response.encode('latin-1'), False  # Repetitive code
            else:
                response = json.dumps({"Status": "Fail", "Reason": "Already Enrolled", "Signature": signed_msg})
                return response.encode('latin-1'), False
        elif verb == 'Login':  # Login is a persistent connection
            challenge = utils.generate_128_bit_random_number()
            if body in self.client_passwords:
                self.hmac_randoms[body] = challenge
                response = json.dumps(
                    {"Status": "Success", "Challenge": challenge.decode('latin-1'), "Signature": signed_msg})
                return response.encode('latin-1'), True     # TODO - remove unnecessary json nesting
            else:
                response = json.dumps({"Status": "Fail", "Reason": "User Does Not Exist, Please Enroll First",
                                       "Signature": signed_msg})
                return response.encode('latin-1'), True
        elif verb == 'HMAC':
            try:
                user = data['Username']
            except Exception:
                response = json.dumps({"Status": "Fail", "Reason": "Bad JSON",
                                       "Signature": signed_msg})
                return response.encode('latin-1'), False
            hmac = body
            if user not in self.hmac_randoms:
                response = json.dumps({"Status": "Fail", "Reason": "User Not Logged In",
                                       "Signature": signed_msg})
                return response.encode('latin-1'), False
            if utils.make_hmac(self.client_passwords[user], self.hmac_randoms[user]) != hmac.encode("latin-1"):
                response = json.dumps({"Status": "Fail", "Reason": "HMAC Does Not Match",
                                       "Signature": signed_msg})
                return response.encode('latin-1'), False

            session_key_enc_dec = utils.generate_128_bit_random_number()
            session_key_signing = utils.generate_128_bit_random_number()

            # TODO Encrypt keys, send them in a JSON, Store the session keys for this client

            response = json.dumps({"Status": "Success", "Signature": signed_msg})
            return response.encode('latin-1'), False  # needs to be true in the future

        response = json.dumps({"Status": "Bad Verb", "Signature": signed_msg})
        return response.encode(), False     # TODO - Should this be latin-1 ?

    # Enroll a user.
    def enroll_user(self, body):
        password_hash = body[-PASSWORD_HASH_LEN:]
        print("Enroll server password hash: " + password_hash)
        username = body[:-PASSWORD_HASH_LEN]
        print("Enroll server username: " + username)
        if username in self.client_passwords:
            self.write_text(f"Client tried to enroll user that already exists! Enrollment failed.")
            return False
        if len(username) + len(password_hash) != len(body):  # Should never happen
            print("Parse error on client probably")
            return False
        self.write_text(f"New enrollment successful!")
        self.client_passwords[username] = password_hash.encode('latin-1')
        return True

    def sign_message(self, hash_msg):
        return utils.sign_message(hash_msg, self.rsa_private_key_signing)
