from flask import Flask, render_template, request, g
import sqlite3
import rsa
import os
from db import init_db

app = Flask(__name__)

keyfiles = [file for file in os.listdir('./keys/') if file.endswith('.pem')]
dbFile = [file for file in os.listdir() if file.endswith('.db')]
if(len(dbFile) == 0 ):
    print('DB Created')
    init_db()

publicKey, privateKey = None, None
if(len(keyfiles) == 0):
    publicKey, privateKey = rsa.newkeys(512)
    with open('./keys/publicKey.pem', 'wb+') as file:
        pubKey = rsa.PublicKey.save_pkcs1(publicKey, format="PEM")
        file.write(pubKey)
    with open('./keys/privateKey.pem', 'wb+') as file:
        privKey = rsa.PrivateKey.save_pkcs1(privateKey, format="PEM")
        file.write(privKey)
else:
    publicKey = rsa.PublicKey.load_pkcs1(open('./keys/publicKey.pem').read())
    privateKey = rsa.PrivateKey.load_pkcs1(open('./keys/privateKey.pem').read())

labelText = "Enter your text here:"
DATABASE = 'encryption.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def main():
    try:
        connection = get_db()
    except sqlite3.OperationalError as err:
        print('Database does not exist!')
    return render_template("index.html", labelText=labelText, decryptStatus="disabled")

@app.route("/", methods = ["POST"])
def encryptor():
    text = request.form["textarea"]
    encryptVal = request.form.get("encryptBtn", default=0)
    decryptVal = request.form.get("decryptBtn", default=0)
    reset = request.form.get("resetBtn", default=0)
    if(encryptVal != 0):
        encryptedMessage = rsa.encrypt(text.encode(), publicKey)
        connection = get_db()
        try:
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            cursor.execute("SELECT plainWord, cipheredWord from Encryption")
            rows = cursor.fetchall()
            for row in rows:
                if(row['plainWord']==text):
                    return render_template("index.html", resultText=row['cipheredWord'], labelText="Encrypted Text:", encryptStatus="disabled")
            cursor.execute("INSERT INTO Encryption(plainWord, cipheredWord) VALUES(?, ?)",(text, encryptedMessage))
            connection.commit()
            print('Inserted Row Successfully')
        except Exception as err:
            connection.rollback()
            print(err)
        finally:
            connection.close()
        return render_template("index.html", resultText=encryptedMessage, labelText="Encrypted Text:", encryptStatus="disabled", decryptStatus="enabled")
    elif(decryptVal != 0):
        text = request.form["textarea"][1:-1]
        connection = get_db()
        try:
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            cursor.execute("SELECT plainWord, cipheredWord from Encryption")
            rows = cursor.fetchall()
            for row in rows:
                if(str(row['cipheredWord'])[1:-1] == text):
                    print(row)
                    ciph = row['cipheredWord']
                    decryptedMessage = rsa.decrypt(ciph, privateKey).decode()
                    return render_template("index.html", resultText=decryptedMessage, labelText="Decrypted Text:", encryptStatus="disabled", decryptStatus="disabled")    
        except Exception as err:
            print(err)
        finally:
            connection.close()
    elif(reset != 0):
        return render_template("index.html", labelText=labelText, encryptStatus="enabled", decryptStatus="disabled")


if __name__ == "__main__":
    app.run()