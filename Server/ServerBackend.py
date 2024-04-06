import socket
import threading
import tkinter as tk

import utils


class ServerInstance:

    def __init__(self):
        self.clients = []
        self.should_listen = False
        self.threads = []
        # Lazy default for debugging
        self.port = '8080'
        self.text_frame = None

    def listen(self, port):
        # TODO - Check if signed in
        if not utils.debug:
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
        print("writing:", text)
        self.text_frame.insert(tk.INSERT, text + "\n")
        self.text_frame.see(tk.END)

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame
