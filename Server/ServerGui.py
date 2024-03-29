import tkinter as tk

def on_ok_click():
    password = password_entry.get()
    # Implement your logic for handling password here
    print("Password entered:", password)

def on_change_click():
    current_password = current_password_entry.get()
    new_password = new_password_entry.get()
    # Implement your logic for changing password here
    print("Current Password:", current_password)
    print("New Password:", new_password)

def on_listen_click():
    port = port_entry.get()
    # Implement your logic for listening on port here
    print("Listening on port:", port)

# Create main window
root = tk.Tk()
root.title("GUI Example")
root.geometry("800x400")

# Left side
left_frame = tk.Frame(root, width=200, height=400)
left_frame.pack_propagate(False)
left_frame.pack(side=tk.LEFT)

password_frame = tk.Frame(left_frame)
password_frame.pack(pady=20, padx=10, side=tk.TOP)

password_label = tk.Label(password_frame, text="Enter Password:")
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

# Right side
right_frame = tk.Frame(root, width=600, height=400)
right_frame.pack_propagate(False)
right_frame.pack(side=tk.RIGHT)

display_text = tk.Text(right_frame)
display_text.pack(fill=tk.BOTH, expand=True)

# Run the application
root.mainloop()
