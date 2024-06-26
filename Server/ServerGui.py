import os
import signal
import tkinter as tk
from tkinter import messagebox
import utils
from ServerBackend import ServerInstance

backend = ServerInstance()


def on_close():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()
        os.kill(os.getpid(), signal.SIGTERM)


def on_ok_click():
    password = password_entry.get()
    if utils.debug and password == "":
        backend.decrypt_keys("Obscurity")
    else:
        backend.decrypt_keys(password)
    password_entry.delete(0, tk.END)  # Clear the password entry box


def on_change_click():
    current_password = current_password_entry.get()
    new_password = new_password_entry.get()
    current_password_entry.delete(0, tk.END)  # Clear the current password entry box
    new_password_entry.delete(0, tk.END)  # Clear the new password entry box
    backend.change_password(current_password, new_password)


def on_listen_click():
    port = port_entry.get()
    backend.listen(port)
    port_entry.delete(0, tk.END)  # Clear the port entry box


# Main window
root = tk.Tk()
root.title("Server")
root.geometry("800x400")

# Left frame
left_frame = tk.Frame(root, width=200, height=400)
left_frame.pack_propagate(False)
left_frame.pack(side=tk.LEFT)

# Password Frame
password_frame = tk.Frame(left_frame)
password_frame.pack(pady=20, padx=10, side=tk.TOP)

password_label = tk.Label(password_frame, text="Password:")
password_label.pack()

password_entry = tk.Entry(password_frame, show="*")
password_entry.pack()

ok_button = tk.Button(password_frame, text="OK", command=on_ok_click)
ok_button.pack(pady=(5, 0))

password_reset_frame = tk.Frame(left_frame)
password_reset_frame.pack(pady=30, padx=10, side=tk.TOP)

current_password_label = tk.Label(password_reset_frame, text="Current Password:")
current_password_label.pack()

current_password_entry = tk.Entry(password_reset_frame, show="*")
current_password_entry.pack()

new_password_label = tk.Label(password_reset_frame, text="New Password:")
new_password_label.pack()

new_password_entry = tk.Entry(password_reset_frame, show="*")
new_password_entry.pack()

change_button = tk.Button(password_reset_frame, text="Change", command=on_change_click)
change_button.pack(pady=(5, 0))

port_frame = tk.Frame(left_frame)
port_frame.pack(pady=20, padx=10, side=tk.BOTTOM)

port_label = tk.Label(port_frame, text="Enter Port:")
port_label.pack()

port_entry = tk.Entry(port_frame)
port_entry.pack()

listen_button = tk.Button(port_frame, text="Listen", command=on_listen_click)
listen_button.pack(pady=(5, 0))

# Right Frame
right_frame = tk.Frame(root, width=600, height=400)
right_frame.pack_propagate(False)
right_frame.pack(side=tk.RIGHT)

display_text = tk.Text(right_frame)
display_text.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

backend.set_text_frame(display_text)
root.protocol("WM_DELETE_WINDOW", on_close)

# Run
root.mainloop()
