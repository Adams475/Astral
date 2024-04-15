import json
import socket
import threading
import tkinter as tk
from Astral import utils

PASSWORD_HASH_LEN = 16  # Magic Number, the password hash sent by the client is 16 bytes long
REQUEST_HEADERS = {'0'.encode(): "RSA", '1'.encode(): "CLEAR-TEXT", '2'.encode(): "AES"}


class ServerInstance:

    def __init__(self):
        self.client_passwords = {}
        self.hmac_randoms = {}
        self.client_enc_dec_session_keys = {}
        self.client_signing_session_keys = {}
        self.should_listen = False
        self.listeners = {}
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
        self.password_changed = False
        utils.check_new_keys()

    def decrypt_keys(self, password):

        # Files with private keys
        encrypted_rsa_key_file_enc_dec = "server/encrypted_server_enc_dec_pub_prv.txt"
        encrypted_rsa_key_file_signing = "server/encrypted_server_signing_verification_pub_prv.txt"

        try:
            # Try to decrypt the keys with the provided password
            self.rsa_private_key_enc_dec = utils.decrypt_rsa_private_key(encrypted_rsa_key_file_enc_dec,
                                                                         password)
            self.rsa_private_key_signing = utils.decrypt_rsa_private_key(encrypted_rsa_key_file_signing,
                                                                         password)
            self.write_text("Keys Decrypted Successfully")
            self.authenticated = True
        except Exception as e:
            self.write_text("Incorrect Password")

    def listen(self, port):
        # If the password was correct then the user should be authenticated. Otherwise they can't start the server
        if not self.authenticated:
            self.write_text("You must login before starting the server")
            return
        if not utils.debug:
            self.port = port

        #  Background thread that accepts connections.
        thread = threading.Thread(target=self.spawn_servers)
        thread.start()

    def spawn_servers(self):
        self.should_listen = True
        server_socket = socket.socket()
        server_name = "127.0.0.1"

        try:
            server_socket.bind((server_name, int(self.port)))
        except OSError as o:
            self.write_text(f"Bind failed, {o}")
            return
        server_socket.listen(3)
        self.write_text(f"Listening on port: {self.port}")

        while self.should_listen:
            connection, addr = server_socket.accept()
            # Once a connection is accepted, create a thread to handle the connecting client
            thread = threading.Thread(target=self.handle_client, args=(connection, addr))
            self.threads.append(thread)
            thread.start()
        print("Should never happen")

    def handle_client(self, connection, addr):
        self.write_text(f"Connection request from address: {addr}")
        response = ""
        while True:
            data = connection.recv(8192)
            client_message = self.parse_raw_data(data)  # Determine if data needs to be decrypted with RSA
            if client_message is None:
                continue
            self.write_text(f"Message from address {addr}: {client_message}")
            response, keep_alive, listen = self.handle_request(client_message, connection)  # Main server logic
            if response is not None:  # Should never be none, if packet is corrupted then should notify client
                self.write_text(f"Response to address {addr}: {response}")
                connection.send(response)
                if listen:  # Thread is later used to broadcast, so we don't want to break and close connection
                    print("returning")
                    return
            if not keep_alive:  # Thread is no longer needed, can break and close connection
                break
        connection.close()

    # Write text to text box on GUI
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
        else:
            # Exception
            return None

    # Parse verb and message body
    def handle_request(self, message, connection):
        data = json.loads(message)
        verb = data['Verb']
        body = data['Body']  # I use body for the signature, no real reason why
        hash_msg = utils.hash_message(body.encode('latin-1'))
        # Make signature. It needs to be decoded into a string because the JSON library cannot serialize the bytes
        # objects that are returned from the Crypto library.
        signed_msg = self.sign_message(hash_msg).decode('latin-1')
        if verb == 'Enroll':
            if self.enroll_user(body):
                response = json.dumps({"Status": "Success", "Signature": signed_msg, "Message": "Done"})
                return response.encode('latin-1'), False, False  # Repetitive code
            else:
                response = json.dumps({"Status": "Fail", "Reason": "Already Enrolled", "Signature": signed_msg,
                                       "Message": "Done"})
                return response.encode('latin-1'), False, False
        elif verb == 'Login':  # Login is a persistent connection
            challenge = utils.generate_128_bit_random_number().decode('latin-1')
            if body in self.client_passwords:
                self.hmac_randoms[body] = challenge
                response = json.dumps(
                    {"Status": "Success", "Challenge": challenge, "Signature": signed_msg,
                     "Message": "Done"})
                return response.encode('latin-1'), True, False  # Persistent connection
            else:
                response = json.dumps({"Status": "Fail", "Reason": "User Does Not Exist, Please Enroll First",
                                       "Signature": signed_msg, "Message": "Done"})
                return response.encode('latin-1'), False, False
        elif verb == 'HMAC':
            # Packet needs to have username, this should never happen
            try:
                user = data['Username']
            except Exception:
                response = json.dumps({"Status": "Fail", "Reason": "Bad JSON",
                                       "Signature": signed_msg, "Message": "Done"})
                return response.encode('latin-1'), False, False
            hmac = body
            # User needs to have a challenge generated from the login elif. If not an error is returned.
            if user not in self.hmac_randoms:
                response = json.dumps({"Status": "Fail", "Reason": "User Not Logged In",
                                       "Signature": signed_msg, "Message": "Done"})
                return response.encode('latin-1'), False, False
            # Check the HMAC.
            if utils.make_hmac(self.client_passwords[user], self.hmac_randoms[user]) != hmac.encode("latin-1"):
                response = json.dumps({"Status": "Fail", "Reason": "HMAC Does Not Match",
                                       "Signature": signed_msg, 'Message': 'Done'})
                return response.encode('latin-1'), False, False
            # User is already connected, need to disconnect the user first.
            if user in self.listeners:
                response = json.dumps({"Status": "Fail", "Reason": "Already signed in at another connection",
                                       "Signature": signed_msg, 'Message': 'Done'})
                print("Disconnecting user")
                # self.disconnect_user(user)
                return response.encode('latin-1'), False, False

            # Create session keys for the current Client session.
            session_key_enc_dec = utils.generate_128_bit_random_number()
            session_key_signing = utils.generate_128_bit_random_number()
            self.client_signing_session_keys[user] = session_key_signing
            self.client_enc_dec_session_keys[user] = session_key_enc_dec
            password_hash = self.client_passwords[user]
            random_challenge = self.hmac_randoms[user]

            cipher = utils.encrypt_AES(password_hash, random_challenge)  # AES has a factory for ciphers?
            encrypted_session_key_enc_dec = cipher.encrypt(session_key_enc_dec).decode('latin-1')
            encrypted_session_key_signing = cipher.encrypt(session_key_signing).decode('latin-1')

            response = json.dumps({"Status": "Success", "Enc_Dec": encrypted_session_key_enc_dec,
                                   "Signing": encrypted_session_key_signing, "Signature": signed_msg,
                                   'Message': 'Listener'})
            self.listeners[user] = connection
            return response.encode('latin-1'), True, True
            # DONE Encrypt keys, send them in a JSON, Store the session keys for this client
        elif verb == 'Disconnect':
            self.disconnect_user(body)
            return None, False, False
        elif verb == 'Broadcast':
            iv = body
            # Check is JSON is the right format
            try:
                msg = data['Message']
                hmac = data['HMAC']
                username = data['Username']
            except Exception as e:
                response = json.dumps({"Status": "Fail", "Reason": "Bad JSON",
                                       "Signature": signed_msg, 'Message': 'Done'})
                self.write_text("Received Bad JSON from Client")
                return response.encode('latin-1'), False, False

            # Check if hmac matches the one stored on client. Don't want a replay attack to be possible.
            if utils.make_hmac(self.client_signing_session_keys[username], msg.encode('latin-1')) != hmac.encode("latin-1"):
                response = json.dumps({"Status": "Fail", "Reason": "HMAC Does Not Match",
                                       "Signature": signed_msg, 'Message': 'Done'})
                return response.encode('latin-1'), False, False

            # Create cipher
            cipher = utils.encrypt_AES(self.client_enc_dec_session_keys[username], iv.encode('latin-1'))
            # Decrypt message from client.
            plaintext = cipher.decrypt(msg.encode('latin-1')).decode('latin-1')
            self.write_text(f"Received message from {username}. Message contents: {plaintext}. Broadcasting message...")
            # Broadcast message to all connected clients
            self.broadcast_message(plaintext, username)
            # Notify the original client that the message was sent successfully.
            response = json.dumps({"Status": "Success", "Reason": "Message Broadcast Successfully!",
                                   "Signature": signed_msg, 'Message': 'Done'})
            return response.encode('latin-1'), False, False

        signed_msg = self.sign_message(hash_msg).decode('latin-1')
        response = json.dumps({"Status": "Bad Verb", "Signature": signed_msg})
        return response.encode('latin-1'), False

    def broadcast_message(self, message, username):
        # For each client currently connected
        for users in self.listeners:
            # Don't broadcast message back to original sender
            if users == username:
                continue
            iv = utils.generate_128_bit_random_number()
            cipher = utils.encrypt_AES(self.client_enc_dec_session_keys[users], iv)
            encrypted_message = cipher.encrypt(message)
            hmac = utils.make_hmac(self.client_signing_session_keys[users], encrypted_message)
            data = json.dumps({"Verb": "Broadcast", "Body": iv.decode('latin-1'),
                               "Message": encrypted_message.decode('latin-1'),
                               "HMAC": hmac.decode('latin-1'),
                               "Username": username}).encode('latin-1')
            try:
                self.listeners[users].send(data)
            except Exception:
                print("Connection died")

    def disconnect_user(self, body):
        password_hash = body[-PASSWORD_HASH_LEN:]
        username = body[:-PASSWORD_HASH_LEN]
        if username not in self.client_passwords:
            self.write_text(f"Client {username} tried to disconnect, but username not in Database")
            return
        if username in self.client_passwords and self.client_passwords[username] != password_hash.encode('latin-1'):
            self.write_text(f"Client {username} tried to disconnect, but password was wrong!")
            return
        self.listeners[username].close()
        del self.listeners[username]
        del self.hmac_randoms[username]
        del self.client_signing_session_keys[username]
        del self.client_enc_dec_session_keys[username]
        self.write_text(f"Disconnected {username} successfully!")
        return

    # Enroll a user.
    def enroll_user(self, body):
        # First, extract username and password from body
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
        self.write_text(f"New enrollment successful! Password {password_hash}")
        self.client_passwords[username] = password_hash.encode('latin-1')
        return True

    def sign_message(self, hash_msg):
        return utils.sign_message(hash_msg, self.rsa_private_key_signing)

    def change_password(self, current_password, new_password):
        # First get file path for encrypted keys
        encrypted_rsa_key_file_enc_dec = "server/encrypted_server_enc_dec_pub_prv.txt"
        encrypted_rsa_key_file_signing = "server/encrypted_server_signing_verification_pub_prv.txt"

        # Make sure input password is correct
        try:
            self.rsa_private_key_enc_dec = utils.decrypt_rsa_private_key(encrypted_rsa_key_file_enc_dec,
                                                                         current_password)
            self.rsa_private_key_signing = utils.decrypt_rsa_private_key(encrypted_rsa_key_file_signing,
                                                                         current_password)
            self.authenticated = True
        except Exception as e:
            print("Error in decoding, most likely incorrect password: ", e)

        # If password fails or isn't correct, error and return
        if not self.authenticated:
            self.write_text("Cannot change password, entered current password is incorrect!")
            return

        # Now that password is correct, re-encrypt the keys using new password has
        # and re-write encrypted password files with newly encrypted keys
        encrypted_rsa_enc_dec = utils.encrypt_rsa_key(self.rsa_private_key_enc_dec, new_password)
        encrypted_rsa_signing = utils.encrypt_rsa_key(self.rsa_private_key_signing, new_password)
        encrypted_rsa_key_file_enc_dec = "server/new_encrypted_server_enc_dec_pub_prv.txt"
        encrypted_rsa_key_file_signing = "server/new_encrypted_server_signing_verification_pub_prv.txt"
        # Can't write a raw byte array to a file in python, so we convert the encrypted data to hex-code
        with open(encrypted_rsa_key_file_enc_dec, "w") as file:
            file.write(encrypted_rsa_enc_dec.hex())
        with open(encrypted_rsa_key_file_signing, "w") as file:
            file.write(encrypted_rsa_signing.hex())
        self.write_text("Password successfully changed!")
        self.write_text("Changes to the password will take effect on next server boot.")
        self.password_changed = True
