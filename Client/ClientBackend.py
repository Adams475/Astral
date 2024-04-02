import socket


class ClientInstance:

    def __init__(self):
        self.server_ip = None
        self.server_port = None
        self.name = None
        self.password = None
        self.connection = None
        self.text_frame = None

    def login(self, server_ip, server_port, name, password):
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

    def send_message(self, message):
        self.connection.send(bytes(message, 'utf-8'))

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame
