import sqlite3

def init_db():
    connection = sqlite3.connect("encryption.db")
    connection.execute("CREATE TABLE Encryption(id INTEGER PRIMARY KEY AUTOINCREMENT, plainWord TEXT NOT NULL UNIQUE, cipheredWord BLOB NOT NULL)")
    connection.close()