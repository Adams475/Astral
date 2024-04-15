import socket
import tkinter as tk
import utils
import json
import threading
from Crypto.Hash import SHA256

# Constants used for network packets
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
        self.logged_in = False

    # Login
    # Initializes variables and server connection, and then hands off the rest of
    # The login protocol to authorize client
    def login(self, server_ip, server_port, name, password):
        # Users aren't allowed to log into another account if they're already logged in
        if self.logged_in:
            self.write_text("Already logged in!")
            return

        # Initialize variables if we aren't in debug mode
        if not utils.debug:
            self.server_ip = server_ip
            self.server_port = server_port
            self.name = name
            self.password = password

        print("Password ", self.password)

        # Debug statement - shouldn't occur
        if self.listening:
            self.write_text("You're already listening, I can't support multiple users on the same window")

        # First initialize connection to server
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

    # Authorize Client
    # Communicates to the server, responding to the challenge and obtaining the symmetric keys used for communication
    # once logged in.
    def authorize_client(self):
        # Create packet to send to server
        # json.dumps forms a json serialized object
        # We use keys verb and body to structure the object
        # Finally, we encode it in latin-1 - this is due to the incompatibility of raw byte arrays and python
        # Latin-1 is a version of character encoding
        data = json.dumps({"Verb": "Login", "Body": self.name}).encode('latin-1')
        full_payload = '1'.encode('latin-1') + data  # Code 1 means clear text
        self.write_text("Sending Authorization Request...")
        self.send_data(full_payload)

        # Listen for response
        server_response = self.listen(self.connection)
        # Hash the name so we can compare the signature
        hashed_msg = utils.hash_message(self.name.encode('latin-1'))

        server_json = json.loads(server_response)

        # Verify signature
        if not self.check_signature(hashed_msg, server_json):
            return
        self.write_text(f"Server Response Verified")

        # Parse json response
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

        # Create password hash
        self.password_hash = SHA256.new(self.password.encode()).digest()

        # Create hmac
        hmac = utils.make_hmac(self.password_hash[:len(self.password_hash) // 2],
                               challenge.encode('latin-1')).decode('latin-1')

        # Form new packet to server containing the response to the challenge
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

        # Finally, create the cipher and decrypt the session keys
        cipher = utils.encrypt_AES(self.password_hash[:16], challenge.encode('latin-1'))
        try:
            enc = server_json['Enc_Dec']
            sig = server_json['Signing']
        except Exception:
            self.write_fail('Enc_Dec or Signing not in server response')
            print(server_json)
            return
        self.session_enc = cipher.decrypt(enc.encode('latin-1'))
        self.session_ver = cipher.decrypt(sig.encode('latin-1'))
        self.write_text("Spawning Listening Thread")
        self.listening_connection = self.connection
        self.logged_in = True
        thread = threading.Thread(target=self.broadcast_listener)
        thread.start()
        print("thread started")

    # Broadcast
    # Called when a user would like to send a message. Sets up the connection to the server
    # and then calls send_broadcast_message
    def broadcast(self, msg):
        # Return if not logged in and listening
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

    # Send_broadcast_message
    # Does the heavy lifting of creating the packet and encrypting it.
    # It then sends the message, and listens to the server for a response
    def send_broadcast_message(self, msg):
        # Cryptography and packet setup
        iv = utils.generate_128_bit_random_number()
        cipher = utils.encrypt_AES(self.session_enc, iv)
        encrypted_message = cipher.encrypt(msg.encode('latin-1'))
        hmac = utils.make_hmac(self.session_ver, encrypted_message)
        data = json.dumps({"Verb": "Broadcast", "Body": iv.decode('latin-1'),
                           "Message": encrypted_message.decode('latin-1'),
                           "HMAC": hmac.decode('latin-1'),
                           "Username": self.name}).encode('latin-1')
        full_payload = '1'.encode('latin-1') + data  # Code 1 means cleartext

        # Send data to server
        self.write_text("Sending broadcast request.")
        self.send_data(full_payload)

        # Wait for response
        server_response = self.listen(self.connection)

        # Generate hash of the iv
        hashed_msg = utils.hash_message(iv)

        # Load the json packet
        server_json = json.loads(server_response)

        # Check for valid signature
        if not self.check_signature(hashed_msg, server_json):
            return

        self.write_text("Server Message Verified")
        code = server_json['Status']

        # Parse the json packet
        if code == 'Success':
            self.write_text("Broadcast Message Sent Successfully")
        elif code == 'Fail':
            self.write_fail(server_json['Reason'])
        elif code == 'Bad Verb':
            self.write_text("Bad Verb! Verb should never be bad?")

    # Broadcast_listener
    # Ran by a thread, this method listens in the background for any messages broadcast by the server and prints
    # them to the text box
    def broadcast_listener(self):
        self.listening = True
        try:
            # Listening loop for thread
            while True:
                server_resp = self.listening_connection.recv(8192)
                data = json.loads(server_resp)
                try:
                    # Parse json packet
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
                # Verify HMAC matches
                if utils.make_hmac(self.session_ver, msg.encode('latin-1')) != hmac.encode("latin-1"):
                    self.write_text("HMAC doesnt match")
                    continue
                # Decrypt the message and print to text box if packet passes all checks
                cipher = utils.encrypt_AES(self.session_enc, iv.encode('latin-1'))
                plaintext = cipher.decrypt(msg.encode('latin-1'))
                self.write_text(f"Received message from {username}, message : {plaintext}")
        except Exception as e:
            self.write_fail("Connection died")
            self.listening = False

    # Init_enroll
    # First stage of enrollment, check if we can connect to server. If so, move on to secure enrollment
    def init_enroll(self, server_ip, server_port, name, password):
        # Stop re-logins
        if self.logged_in:
            self.write_text("Already logged in! Can't enroll while logged in.")
            return

        # Initialize values if not in debug mode
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

    # Secure_enroll
    # Encrypts user data and sends it to the server for enrollment
    def secure_enroll(self):
        self.password_hash = SHA256.new(self.password.encode()).digest()
        # Concatenate the most significant half of the hash with the username
        # I need to switch the encoding to latin-1 since I can't serialize a bytes array in json, and utf-8 can't
        # handle arbitrary bit strings...
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

    # Disconnect
    # Gracefully disconnects from server, letting it know that it should close its connection to the client
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

        # Encrypt message to server so a random user can't disconnect you
        self.password_hash = SHA256.new(self.password.encode()).digest()
        concatenated_message = self.name.encode('utf-8').decode('latin-1') + self.password_hash[
                                                                             :len(self.password_hash) // 2].decode(
            'latin-1')
        data = json.dumps({"Verb": "Disconnect", "Body": concatenated_message}).encode('latin-1')
        encrypted_message = self.encrypt_message(data)
        full_payload = '0'.encode('latin-1') + encrypted_message  # Code 0 means RSA encrypted
        self.write_text("Disconnecting")
        self.send_data(full_payload)

    # Send_data
    # Basic function to send data to the server as well as write what is sent to the text box
    def send_data(self, data):
        self.write_text(data)
        self.connection.send(data)

    # Write_text
    # Simple function to write to the text box
    def write_text(self, text):
        self.text_frame.insert(tk.INSERT, text.__str__() + "\n")
        self.text_frame.see(tk.END)

    # Set_text_frame
    # Used by the gui to set this instances text frame to its text box
    def set_text_frame(self, text_frame):
        self.text_frame = text_frame

    # Listen
    # Wrapper function for handling a socket
    def listen(self, sock):
        # NOTE - Currently, assuming this data decodes to a string
        self.write_text("Waiting for server response...")
        data = sock.recv(8192)
        return data

    # Encrypt_message
    # Wrapper for utils.encrypt_message
    def encrypt_message(self, message):
        return utils.encrypt_message(message, self.public_enc)

    # Verify_message
    # Wrapper for utils.verify_message
    def verify_message(self, hashed_message, signature):
        return utils.verify_message(hashed_message, self.public_sig, signature)

    # write_fail
    # Simple function to prefix a write with failure text
    def write_fail(self, reason):
        self.write_text(f"Server returned failure! Reason: {reason}")

    # Check_signature
    # Verifies if signature from the server is valid
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
