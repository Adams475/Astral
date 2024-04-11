import socket
import tkinter as tk
import utils
import json
import base64

from Crypto.Hash import SHA256

# Magic Nums
VERB_LEN = 5
CHALLENGE_LEN = 16


class ClientInstance:

    def __init__(self, public_enc, public_sig):
        self.public_enc = public_enc
        self.public_sig = public_sig
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

    def login(self, server_ip, server_port, name, password):
        if not utils.debug:
            self.server_ip = server_ip
            self.server_port = server_port
            self.name = name
            self.password = password

        # First initialize connection to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, int(self.server_port)))
            self.connection = sock
        except Exception as e:
            self.write_text("Unable to connect to the server at the specified address and port!")
            print("connection failure: ", e)

        # Now attempt authorization with server
        try:
            self.authorize_client()
        except Exception as e:
            self.write_text("Authorize client failed!")
            print("authorize client failure: ", e)

        # Finally, terminate connection with server
        try:
            self.connection.close()
        except Exception as e:
            self.write_text("Unable to gracefully close socket!")
            print("socket closure failure: ", e)

    def authorize_client(self):
        data = json.dumps({"Verb": "Login", "Body": self.name}).encode('latin-1')
        full_payload = '1'.encode('latin-1') + data  # Code 1 means clear text
        self.write_text("Sending Authorization Request...")
        self.send_data(full_payload)

        server_response = self.listen(self.connection)
        hashed_msg = utils.hash_message(self.name.encode('latin-1'))

        # TODO Figure out why the fck this works
        server_json = json.loads(server_response)  # ???????? WHY DOES IT ONLY WORK IF I NEST IT

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

        self.write_text("Success!")

        # Todo Finish the rest :P :3

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
        # NOTE - Currently, assuming this data decodes to a string
        self.write_text("Waiting for server response...")
        data = sock.recv(8192)
        # TODO find out proper way for finding out if client wants to close connection
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

        # TODO Try to remove redundant encodes and decodes, I dont know if its possible but they are ugly
        if not self.verify_message(hashed_msg, server_json['Signature'].encode('latin-1')):
            self.write_text(f"Server Message Not Verified")
            return False
        return True
