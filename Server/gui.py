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
root.geometry("800x600")

# Left side
left_frame = tk.Frame(root, width=200, height=600)
left_frame.pack_propagate(False)
left_frame.pack(side=tk.LEFT)

password_label = tk.Label(left_frame, text="Enter Password:")
password_label.pack()

password_entry = tk.Entry(left_frame, show="*")
password_entry.pack()

ok_button = tk.Button(left_frame, text="OK", command=on_ok_click)
ok_button.pack()

current_password_label = tk.Label(left_frame, text="Current Password:")
current_password_label.pack()

current_password_entry = tk.Entry(left_frame, show="*")
current_password_entry.pack()

new_password_label = tk.Label(left_frame, text="New Password:")
new_password_label.pack()

new_password_entry = tk.Entry(left_frame, show="*")
new_password_entry.pack()

change_button = tk.Button(left_frame, text="Change", command=on_change_click)
change_button.pack()

port_label = tk.Label(left_frame, text="Enter Port:")
port_label.pack()

port_entry = tk.Entry(left_frame)
port_entry.pack()

listen_button = tk.Button(left_frame, text="Listen", command=on_listen_click)
listen_button.pack()

# Right side
right_frame = tk.Frame(root, width=600, height=600)
right_frame.pack_propagate(False)
right_frame.pack(side=tk.RIGHT)

display_text = tk.Text(right_frame)
display_text.pack(fill=tk.BOTH, expand=True)

# Run the application
root.mainloop()
