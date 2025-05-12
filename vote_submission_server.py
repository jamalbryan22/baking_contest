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
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import base64
import sqlite3

SECRET_KEY = b"myverysecurekeyy"  # Ensure this key is exactly 16 bytes
DATABASE_PATH = 'baking_contest.db'

def decrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(data))
    return unpad(decrypted, AES.block_size).decode()

class VoteHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024).strip()
        try:
            # Decrypt the received message
            message = decrypt_data(data.decode())
            entry_id, excellent_votes, ok_votes, bad_votes = message.split("^%$")

            # Validate the data
            if not entry_id.isdigit() or int(entry_id) <= 0:
                self.request.sendall(b"Invalid EntryId: must be numeric and > 0.")
                return
            if not excellent_votes.isdigit() or int(excellent_votes) < 0:
                self.request.sendall(b"Invalid Excellent Votes: must be numeric and >= 0.")
                return
            if not ok_votes.isdigit() or int(ok_votes) < 0:
                self.request.sendall(b"Invalid Ok Votes: must be numeric and >= 0.")
                return
            if not bad_votes.isdigit() or int(bad_votes) < 0:
                self.request.sendall(b"Invalid Bad Votes: must be numeric and >= 0.")
                return

            # Update the database
            conn = sqlite3.connect(DATABASE_PATH)
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM BakingContestEntry WHERE EntryId = ?", (entry_id,))
            if not cur.fetchone():
                self.request.sendall(b"EntryId does not exist in the database.")
                conn.close()
                return

            cur.execute('''
                UPDATE BakingContestEntry
                SET NumExcellentVotes = NumExcellentVotes + ?,
                    NumOkVotes = NumOkVotes + ?,
                    NumBadVotes = NumBadVotes + ?
                WHERE EntryId = ?
            ''', (int(excellent_votes), int(ok_votes), int(bad_votes), int(entry_id)))
            conn.commit()
            conn.close()

            self.request.sendall(b"Vote successfully processed.")
        except Exception as e:
            error_message = f"Error processing vote: {e}".encode()
            self.request.sendall(error_message)

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    with socketserver.TCPServer((HOST, PORT), VoteHandler) as server:
        print(f"Server started at {HOST}:{PORT}")
        server.serve_forever()
