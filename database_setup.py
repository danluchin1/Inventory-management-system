import sqlite3

def setup_database():
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    # Create Products table
    cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                        product_id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        price REAL NOT NULL,
                        stock INTEGER NOT NULL
                    )''')

    # Create Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        user_id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    )''')
    
    conn.commit()
    conn.close()

setup_database()
