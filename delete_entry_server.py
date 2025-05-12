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

import socketserver
import hmac
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import sqlite3

# Constants
HOST = "localhost"
PORT = 8888
SECRET_KEY = b"myverysecurekeyy"  # Ensure this key is exactly 16 bytes
BLOCK_SIZE = 16  # AES block size


class DeleteEntryRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            # Receive data
            data = self.request.recv(1024)
            if not data:
                self.request.sendall(b"Error: No data received.")
                return

            # Split the HMAC and encrypted message
            hmac_signature = data[:64]
            encrypted_message = data[64:]

            # Authenticate the message
            computed_hmac = hmac.new(SECRET_KEY, encrypted_message, hashlib.sha3_512).digest()
            if not hmac.compare_digest(hmac_signature, computed_hmac):
                self.request.sendall(
                    b"Unauthenticated Delete Baking Contest Entry message received! Be on alert!"
                )
                return

            # Decrypt the message
            try:
                cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=encrypted_message[:16])
                decrypted_message = unpad(
                    cipher.decrypt(encrypted_message[16:]), BLOCK_SIZE
                ).decode()
            except Exception as e:
                self.request.sendall(
                    f"Decryption error: {str(e)}".encode()
                )
                return

            # Extract EntryId from the message
            try:
                entry_id = int(decrypted_message.split("=")[1])
                if entry_id <= 0:
                    self.request.sendall(
                        b"Validation Failed: EntryId must be greater than 0."
                    )
                    return
            except (ValueError, IndexError) as e:
                self.request.sendall(
                    f"Validation Failed: Invalid message format. Error: {str(e)}".encode()
                )
                return

            # Check and delete entry in the database
            try:
                conn = sqlite3.connect("baking_contest.db")
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM BakingContestEntry WHERE EntryId = ?", (entry_id,)
                )
                entry = cursor.fetchone()
                if not entry:
                    self.request.sendall(
                        f"Validation Failed: EntryId {entry_id} does not exist.".encode()
                    )
                    conn.close()
                    return

                cursor.execute(
                    "DELETE FROM BakingContestEntry WHERE EntryId = ?", (entry_id,)
                )
                conn.commit()
                conn.close()
                self.request.sendall(
                    f"EntryId {entry_id} successfully deleted.".encode()
                )
            except sqlite3.Error as db_error:
                self.request.sendall(f"Database error: {str(db_error)}".encode())
                return

        except Exception as e:
            self.request.sendall(f"Unhandled server error: {str(e)}".encode())


if __name__ == "__main__":
    with socketserver.TCPServer((HOST, PORT), DeleteEntryRequestHandler) as server:
        print(f"Delete Entry Server started on {HOST}:{PORT}")
        server.serve_forever()
