import socket
import tkinter as tk
from Astral import utils
import json
import threading
import base64

from Crypto.Hash import SHA256

# Magic Nums
VERB_LEN = 5
CHALLENGE_LEN = 16


class ClientInstance:

    def __init__(self, public_enc, public_sig):
        self.public_enc = public_enc
        self.public_sig = public_sig
        self.session_enc = None
        self.session_ver = None
        # Lazy defaults for debugging
        if utils.debug:
            self.server_ip = "127.0.0.1"
            self.server_port = "8080"
            self.name = "q"
            self.password = "Obscurity"
        else:
            self.server_ip = None
            self.server_port = None
            self.name = None
            self.password = None
        self.password_hash = None
        self.connection = None
        self.text_frame = None
        self.server_response = None
        self.listening = False
        self.listening_connection = None

    def login(self, server_ip, server_port, name, password):
        if not utils.debug:
            self.server_ip = server_ip
            self.server_port = server_port
            self.name = name
            self.password = password

        # First initialize connection to server
        if self.listening:
            self.write_text("Your already listening bro, I can't support multiple users on the same window")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, int(self.server_port)))
            self.connection = sock
        except Exception as e:
            self.write_text("Unable to connect to the server at the specified address and port!")
            print("connection failure: ", e)
            return

        # Now attempt authorization with server
        try:
            self.authorize_client()
        except Exception as e:
            self.write_text("Authorize client failed!")
            print("authorize client failure: ", e)

        # Finally, terminate connection with server
        #try:
        #    self.connection.close()
        #except Exception as e:
        #    self.write_text("Unable to gracefully close socket!")
        #    print("socket closure failure: ", e)

    def authorize_client(self):
        data = json.dumps({"Verb": "Login", "Body": self.name}).encode('latin-1')
        full_payload = '1'.encode('latin-1') + data  # Code 1 means clear text
        self.write_text("Sending Authorization Request...")
        self.send_data(full_payload)

        server_response = self.listen(self.connection)
        hashed_msg = utils.hash_message(self.name.encode('latin-1'))

        server_json = json.loads(server_response)

        if not self.check_signature(hashed_msg, server_json):
            return
        self.write_text(f"Server Response Verified")

        code = server_json['Status']  # Status code is first field
        if code == "Fail":
            self.write_fail(server_json['Reason'])
            return

        try:
            challenge = server_json['Challenge']
        except Exception as a:
            self.write_fail("Challenge was not part of the json")
            return

        self.write_text(f"Challenge received: {challenge}")
        self.write_text(f"Challenge received: {challenge.encode('latin-1')}")

        hmac = utils.make_hmac(self.password_hash[:len(self.password_hash) // 2],
                               challenge.encode('latin-1')).decode('latin-1')

        data = json.dumps({"Verb": "HMAC", "Body": hmac, "Username": self.name}).encode('latin-1')
        full_payload = '1'.encode() + data  # Code 1 means clear text
        self.write_text("Sending HMAC...")
        self.send_data(full_payload)

        server_response = self.listen(self.connection)
        hashed_msg = utils.hash_message(hmac.encode('latin-1'))

        server_json = json.loads(server_response)

        if not self.check_signature(hashed_msg, server_json):
            return

        code = server_json['Status']  # Status code is first field
        if code == "Fail":
            self.write_fail(server_json['Reason'])
            return

        cipher = utils.encrypt_AES(self.password_hash[:16], challenge.encode('latin-1'))
        print("hi")
        try:
            enc = server_json['Enc_Dec']
            sig = server_json['Signing']
            print(enc, sig)
        except Exception:
            self.write_fail('Enc_Dec or Signing not in server response')
            print(server_json)
            return
        self.session_enc = cipher.decrypt(enc.encode('latin-1'))
        self.session_ver = cipher.decrypt(sig.encode('latin-1'))
        self.write_text("Spawning Listening Thread")
        self.listening_connection = self.connection
        thread = threading.Thread(target=self.broadcast_listener)
        thread.start()
        print("thread started")

    def broadcast(self, msg):
        if not self.listening:
            self.write_text("Need to be logged in and active in server to send messages!")
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, int(self.server_port)))
            self.connection = sock
            print(self.connection)
        except Exception as e:
            self.write_text("Unable to connect to the server at the specified address and port!")
            print("connection failure: ", e)
        try:
            self.send_broadcast_message(msg)
        except Exception as e:
            self.write_text("Broadcast client failed!")
            print("Broadcast client failure: ", e)

    # Can't use self.connection since that is being used to listen. I need it for disconnect.
    def send_broadcast_message(self, msg):
        iv = utils.generate_128_bit_random_number()
        print(self.session_enc, iv)
        cipher = utils.encrypt_AES(self.session_enc, iv)
        encrypted_message = cipher.encrypt(msg.encode('latin-1'))
        hmac = utils.make_hmac(self.session_ver, encrypted_message)
        print(f'sess')
        print(f"HMAC {hmac.decode('latin-1')}, session_ver = {self.session_ver}, encrypted_message = {encrypted_message.decode('latin-1')}")
        data = json.dumps({"Verb": "Broadcast", "Body": iv.decode('latin-1'),
                           "Message": encrypted_message.decode('latin-1'),
                           "HMAC": hmac.decode('latin-1'),
                           "Username": self.name}).encode('latin-1')
        full_payload = '1'.encode('latin-1') + data  # Code 1 means cleartext

        self.write_text("Sending broadcast request.")
        self.send_data(full_payload)
        server_response = self.listen(self.connection)
        hashed_msg = utils.hash_message(iv)

        server_json = json.loads(server_response)

        if not self.check_signature(hashed_msg, server_json):
            return

        self.write_text("Server Message Verified")
        code = server_json['Status']

        if code == 'Success':
            self.write_text("Broadcast Message Sent Successfully")
        elif code == 'Fail':
            self.write_fail(server_json['Reason'])
        elif code == 'Bad Verb':
            self.write_text("Bad Verb! Verb should never be bad?")

    def broadcast_listener(self):
        self.listening = True
        try:
            while True:
                print('Hi')
                server_resp = self.listening_connection.recv(8192)
                print(server_resp)
                data = json.loads(server_resp)
                try:
                    verb = data['Verb']
                    body = data['Body']  # I use body for the signature, no real reason why
                    iv = body
                    msg = data['Message']
                    hmac = data['HMAC']
                    username = data['Username']
                except Exception as e:
                    self.write_text("Bad JSON from server")
                    continue
                if verb != 'Broadcast':
                    self.write_text("Bad JSON from server")
                    continue
                if utils.make_hmac(self.session_ver, msg.encode('latin-1')) != hmac.encode("latin-1"):
                    self.write_text("HMAC doesnt match")
                    continue
                cipher = utils.encrypt_AES(self.session_enc, iv.encode('latin-1'))
                plaintext = cipher.decrypt(msg.encode('latin-1'))
                self.write_text(f"Received message from {username}, message : {plaintext}")
        except Exception as e:
            self.write_fail("Connection died")
            self.listening = False

    # First stage of enrollment, check if we can connect to server. If so, move on to secure enrollment
    def init_enroll(self, server_ip, server_port, name, password):
        if not utils.debug:
            self.server_ip = server_ip
            self.server_port = server_port
            self.name = name
            self.password = password

        if ":" in name:
            self.write_text("Name cannot contain colon character ':'")
            return

        # First initialize connection to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, int(self.server_port)))
            self.connection = sock
        except Exception as e:
            self.write_text("Unable to connect to the server at the specified address and port!")
            print("connection failure: ", e)

        # Once connected to server, continue to secure enrollment
        try:
            self.secure_enroll()
        except Exception as e:
            self.write_text("Secure enroll failed!")
            print("secure enroll failure: ", e)

        # Finally, terminate connection with server
        try:
            self.connection.close()
        except Exception as e:
            self.write_text("Failed to close connection to server!")
            print("socket closure failure: ", e)

    def secure_enroll(self):
        self.password_hash = SHA256.new(self.password.encode()).digest()
        # Concatenate the most significant half of the hash with the username
        # I need to switch the encoding to latin-1 since I can't serialize a bytes array in json, and utf-8 can't
        # handle arbitrary bit strings...
        print("Enroll client password hash: " + self.password_hash.decode('latin-1'))
        concatenated_message = self.name.encode('utf-8').decode('latin-1') + self.password_hash[
                                                                             :len(self.password_hash) // 2].decode(
            'latin-1')
        data = json.dumps({"Verb": "Enroll", "Body": concatenated_message}).encode('latin-1')

        # self.write_text(f"Sending message before encryption: {concatenated_message}")
        # Encrypt the concatenated message using the RSA public key of the server
        encrypted_message = self.encrypt_message(data)
        full_payload = '0'.encode('latin-1') + encrypted_message  # Code 0 means RSA encrypted

        self.write_text("Sending enrollment request.")
        self.send_data(full_payload)
        print("Hello?")

        server_response = self.listen(self.connection)
        hashed_msg = utils.hash_message(concatenated_message.encode('latin-1'))

        # Fixed :)
        server_json = json.loads(server_response)

        if not self.check_signature(hashed_msg, server_json):
            return

        self.write_text("Server Message Verified")
        # self.write_text(f"Server plaintext response: {server_response}")
        code = server_json['Status']

        if code == 'Success':
            self.write_text("Enrollment Successful")
            self.write_text("You may login now!")
        elif code == 'Fail':
            self.write_fail(server_json['Reason'])
        elif code == 'Bad Verb':
            self.write_text("Bad Verb! Should have sent Enroll:")

    def disconnect(self):
        print("Disconnect... self.listening is", self.listening)
        if not self.listening:
            return
        self.listening_connection.close()
        self.listening = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, int(self.server_port)))
            self.connection = sock
        except Exception as e:
            self.write_text("Unable to connect to the server at the specified address and port!")
            print("connection failure: ", e)

        self.password_hash = SHA256.new(self.password.encode()).digest()
        concatenated_message = self.name.encode('utf-8').decode('latin-1') + self.password_hash[
                                                                             :len(self.password_hash) // 2].decode(
            'latin-1')
        data = json.dumps({"Verb": "Disconnect", "Body": concatenated_message}).encode('latin-1')
        encrypted_message = self.encrypt_message(data)
        full_payload = '0'.encode('latin-1') + encrypted_message  # Code 0 means RSA encrypted
        self.write_text("Disconnecting")
        self.send_data(full_payload)


    def send_data(self, data):
        print("sending:", data)
        self.write_text(data)
        self.connection.send(data)

    def write_text(self, text):
        self.text_frame.insert(tk.INSERT, text.__str__() + "\n")
        self.text_frame.see(tk.END)

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame

    def listen(self, sock):
        # NOTE - Currently, assuming this data decodes to a string
        self.write_text("Waiting for server response...")
        data = sock.recv(8192)
        return data

    def encrypt_message(self, message):
        return utils.encrypt_message(message, self.public_enc)

    def verify_message(self, hashed_message, signature):
        return utils.verify_message(hashed_message, self.public_sig, signature)

    def write_fail(self, reason):
        self.write_text(f"Server returned failure! Reason: {reason}")

    def check_signature(self, hashed_msg, server_json):
        try:
            server_json['Signature']
        except Exception as a:
            self.write_text("Not in JSON format, aborting")
            return False

        if not self.verify_message(hashed_msg, server_json['Signature'].encode('latin-1')):
            self.write_text(f"Server Message Not Verified")
            return False
        return True
