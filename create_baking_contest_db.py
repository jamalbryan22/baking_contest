"""
Name: Jamal Bryan
Date: 12/04/2024
Assignment: Module 14: Send Authenticated Message
Due Date: 12/04/2024
About this project:
Solve a simple programming problem based on various approaches to computer security and information management.
Build a small scale real-world application that incorporates the principles of secure computing including cryptography, network security, and data protection.
Build small scale real-world applications using third-party Python libraries discussed in the course.
Choose the best library for an application by examining the benefits of various libraries currently used by the industry.
Apply Python towards several contemporary programming requirements and techniques involving secure, distributed, and parallel computing.
Using Python and the hmac, hashlib, and pycryptodome libraries
Assumptions:
The application creates the database upon execution.
In order to access all functionality you must sign in as a user with the highest security level (3)
If you change the application secret key you must ensure they are consistent across the different servers, and it must be 16 bytes
The create_baking_contest_db.py script has to be run first.
All work below was performed by Jamal Bryan
"""

import sqlite3
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64

# Fixed AES key (16 bytes, must be kept secret and consistent)
SECRET_KEY = b"myverysecurekeyy"  # Ensure this key is exactly 16 bytes

# Encrypt data using AES in ECB mode
def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

# Decrypt data using AES in ECB mode
def decrypt_data(data):
    # Ensure the input data has correct padding for base64
    if len(data) % 4 != 0:
        data += "=" * (4 - len(data) % 4)  # Add missing '=' padding

    try:
        cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(data))
        return unpad(decrypted, AES.block_size).decode()
    except (ValueError, base64.binascii.Error) as e:
        raise ValueError(f"Decryption failed: {e}")

# Create and populate the database
def create_and_populate_db():
    conn = sqlite3.connect("baking_contest.db")
    cur = conn.cursor()

    # Drop the table if it exists
    cur.execute("DROP TABLE IF EXISTS BakingContestPeople")

    # Create the BakingContestPeople table
    cur.execute('''
        CREATE TABLE BakingContestPeople (
            UserId INTEGER PRIMARY KEY,
            Name TEXT NOT NULL,
            Age INTEGER,
            PhNum TEXT,
            SecurityLevel INTEGER,
            LoginPassword TEXT NOT NULL
        )
    ''')

    # Create the BakingContestEntry table with foreign key reference to BakingContestPeople
    cur.execute('''
        CREATE TABLE IF NOT EXISTS BakingContestEntry (
            EntryId INTEGER PRIMARY KEY,
            UserId INTEGER,
            NameOfBakingItem TEXT NOT NULL,
            NumExcellentVotes INTEGER,
            NumOkVotes INTEGER,
            NumBadVotes INTEGER,
            FOREIGN KEY (UserId) REFERENCES BakingContestPeople(UserId)
        )
    ''')

    # Insert data with encrypted fields
    users = [
        (1, "Alice", 30, "123-456-7890", 3, "password1"),
        (2, "Bob", 25, "234-567-8901", 2, "password2"),
        (3, "Charlie", 28, "345-678-9012", 1, "password3"),
        (4, "Diana", 35, "456-789-0123", 3, "password4"),
        (5, "Eve", 40, "567-890-1234", 2, "password5"),
        (6, "Frank", 22, "678-901-2345", 1, "password6"),
    ]

    for user in users:
        cur.execute('''
            INSERT INTO BakingContestPeople (UserId, Name, Age, PhNum, SecurityLevel, LoginPassword)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user[0],
            encrypt_data(user[1]),  # Encrypt the name
            user[2],
            encrypt_data(user[3]),  # Encrypt the phone number,
            user[4],
            encrypt_data(user[5])  # Encrypt the password

        ))

    conn.commit()

    # Fetch and display all rows (decrypted for debugging purposes)
    cur.execute("SELECT * FROM BakingContestPeople")
    rows = cur.fetchall()
    print("Stored Data:")
    for row in rows:
        print(f"UserId: {row[0]}, Name: {decrypt_data(row[1])}, "
              f"Age: {row[2]}, PhNum: {decrypt_data(row[3])}, "
              f"SecurityLevel: {row[4]}, LoginPassword: {decrypt_data(row[5])}")

    conn.close()

if __name__ == "__main__":
    create_and_populate_db()
