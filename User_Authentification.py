# 1. Setting Up the Database for User Authentication
import sqlite3
import bcrypt

def setup_database():
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    # Create Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        user_id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    )''')
    conn.commit()
    conn.close()

setup_database()

# 2. User Registration Function

def register_user(username, password):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    # Hash the password before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        print("User registered successfully!")
    except sqlite3.IntegrityError:
        print("Username already exists!")
    finally:
        conn.close()

# 3. User Login Function

def login_user(username, password):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    
    conn.close()

    if result:
        stored_password = result[0]
        # Compare the hashed password
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            print("Login successful!")
            return True
        else:
            print("Incorrect password!")
    else:
        print("Username not found!")
    
    return False

# 4. Session Management

current_user = None

def login_user(username, password):
    global current_user
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()

    conn.close()

    if result:
        stored_password = result[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            print("Login successful!")
            current_user = username  # Set session
            return True
        else:
            print("Incorrect password!")
    else:
        print("Username not found!")

    return False

def logout_user():
    global current_user
    current_user = None
    print("User logged out.")

# 5. Adding a Login GUI with Tkinter

import tkinter as tk
from tkinter import messagebox

# GUI for login
def login_gui():
    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()
        if login_user(username, password):
            messagebox.showinfo("Success", "Login successful!")
            inventory_screen()  # Proceed to inventory screen after login
        else:
            messagebox.showerror("Error", "Login failed!")

    # Create login window
    login_window = tk.Tk()
    login_window.title("Login")

    tk.Label(login_window, text="Username").grid(row=0, column=0)
    username_entry = tk.Entry(login_window)
    username_entry.grid(row=0, column=1)

    tk.Label(login_window, text="Password").grid(row=1, column=0)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.grid(row=1, column=1)

    login_button = tk.Button(login_window, text="Login", command=attempt_login)
    login_button.grid(row=2, column=0, columnspan=2)

    login_window.mainloop()

# GUI for registration
def register_gui():
    def attempt_register():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            register_user(username, password)
            messagebox.showinfo("Success", "User registered successfully!")
        else:
            messagebox.showerror("Error", "Please fill in both fields.")

    # Create registration window
    register_window = tk.Tk()
    register_window.title("Register")

    tk.Label(register_window, text="Username").grid(row=0, column=0)
    username_entry = tk.Entry(register_window)
    username_entry.grid(row=0, column=1)

    tk.Label(register_window, text="Password").grid(row=1, column=0)
    password_entry = tk.Entry(register_window, show="*")
    password_entry.grid(row=1, column=1)

    register_button = tk.Button(register_window, text="Register", command=attempt_register)
    register_button.grid(row=2, column=0, columnspan=2)

    register_window.mainloop()

# Example function to restrict access to the inventory screen
def inventory_screen():
    if not current_user:
        messagebox.showerror("Error", "You must be logged in to access the inventory!")
        return

    inventory_window = tk.Tk()
    inventory_window.title("Inventory")

    tk.Label(inventory_window, text="Welcome to the inventory management system!").pack()

    inventory_window.mainloop()

# Start the application with login and registration options
def start_app():
    root = tk.Tk()
    root.title("Inventory Management System - Auth")

    login_button = tk.Button(root, text="Login", command=login_gui)
    login_button.pack(pady=10)

    register_button = tk.Button(root, text="Register", command=register_gui)
    register_button.pack(pady=10)

    root.mainloop()

start_app()
