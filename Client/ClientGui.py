import tkinter as tk
from Client.ClientBackend import ClientInstance

backend = ClientInstance()

def on_login_click():
    ip = ip_entry.get()
    port = port_entry.get()
    name = name_entry.get()
    password = password_entry.get()

    backend.login(ip, port, name, password)



def on_enroll_click():
    ip = ip_entry.get()
    port = port_entry.get()
    name = name_entry.get()
    password = password_entry.get()
    # Implement your logic for enrollment here
    print("Enrollment details - IP:", ip, "Port:", port, "Name:", name, "Password:", password)


def on_send_click():
    message = message_entry.get()
    print("sending: ", message)
    backend.send_message(message)


# Create main window
root = tk.Tk()
root.title("Client")
root.geometry("925x500")

# Left side
left_frame = tk.Frame(root)
left_frame.grid(row=0, column=0, padx=10, pady=10)

ip_label = tk.Label(left_frame, text="IP:")
ip_label.grid(row=0, column=0, padx=(0, 5))

ip_entry = tk.Entry(left_frame)
ip_entry.grid(row=0, column=1, padx=(5, 0))

port_label = tk.Label(left_frame, text="Port:")
port_label.grid(row=1, column=0, padx=(0, 5))

port_entry = tk.Entry(left_frame)
port_entry.grid(row=1, column=1, padx=(5, 0))

name_label = tk.Label(left_frame, text="Name:")
name_label.grid(row=2, column=0, padx=(0, 5))

name_entry = tk.Entry(left_frame)
name_entry.grid(row=2, column=1, padx=(5, 0))

password_label = tk.Label(left_frame, text="Password:")
password_label.grid(row=3, column=0, padx=(0, 5))

password_entry = tk.Entry(left_frame, show="*")
password_entry.grid(row=3, column=1, padx=(5, 0))

login_button = tk.Button(left_frame, text="Login", command=on_login_click)
login_button.grid(row=4, column=0, columnspan=2, pady=(20, 5))

enroll_button = tk.Button(left_frame, text="Enroll", command=on_enroll_click)
enroll_button.grid(row=5, column=0, columnspan=2, pady=(5, 20))

# Right side
right_frame = tk.Frame(root)
right_frame.grid(row=0, column=1, padx=10, pady=10)

display_text = tk.Text(right_frame)
display_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Bottom side
bottom_frame = tk.Frame(root)
bottom_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

message_label = tk.Label(bottom_frame, text="Message:")
message_label.pack(side=tk.LEFT, padx=(0, 5))

message_entry = tk.Entry(bottom_frame)
message_entry.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=(5, 10))

send_button = tk.Button(bottom_frame, text="Send", command=on_send_click)
send_button.pack(side=tk.RIGHT, padx=(0, 5))

# Run the application
root.mainloop()
