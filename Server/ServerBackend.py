import socket
import threading
import tkinter as tk


class ServerInstance:

    def __init__(self):
        self.clients = []
        self.should_listen = False
        self.threads = []
        self.port = None
        self.text_frame = None

    def listen(self, port):
        # TODO - Check if signed in
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
            data = connection.recv(8192)
            # TODO make text box follow newest line
            self.text_frame.insert(tk.INSERT, data.decode() + "\n")
            self.text_frame.see(tk.END)
        # conn.sendall(reply)
        conn.close()

    def set_text_frame(self, text_frame):
        self.text_frame = text_frame
