from cryptography.fernet import Fernet
import sqlite3
import hashlib
from flask import Flask, request, jsonify
import sqlite3
from cryptography.fernet import Fernet
import hashlib
app = Flask(__name__)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username and password:
        register_user(username, password)
        return jsonify({"message": "Đăng ký thành công!"}), 201
    return jsonify({"error": "Thiếu thông tin đăng ký."}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user_id = login_user(username, password)
    if user_id:
        return jsonify({"message": "Đăng nhập thành công!", "user_id": user_id}), 200
    return jsonify({"error": "Đăng nhập thất bại."}), 401

@app.route('/add_account', methods=['POST'])
def add_account_endpoint():
    data = request.json
    user_id = data.get('user_id')
    identifier = data.get('identifier')
    account_data = data.get('account_data')
    if user_id and identifier and account_data:
        add_account(user_id, identifier, account_data)
        return jsonify({"message": "Tài khoản đã được lưu!"}), 200
    return jsonify({"error": "Thiếu thông tin."}), 400
# Load or generate encryption key
def load_key():
    try:
        with open("key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        return key

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# User management
def register_user(username, password):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    try:
        password_hash = hash_password(password)
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        print("Đăng ký thành công!")
    except sqlite3.IntegrityError:
        print("Tên đăng nhập đã tồn tại.")
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    password_hash = hash_password(password)
    c.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
    user = c.fetchone()
    conn.close()
    if user:
        print("Đăng nhập thành công!")
        return user[0]  # Return user ID
    else:
        print("Tên đăng nhập hoặc mật khẩu không đúng.")
        return None

# Encryption helpers
def encrypt_data(data):
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data).decode()

# Database initialization
def init_db():
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    identifier TEXT,
                    data TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    conn.commit()
    conn.close()

# Account management
def add_account(user_id, identifier, data):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    encrypted_data = encrypt_data(data)
    c.execute("INSERT INTO accounts (user_id, identifier, data) VALUES (?, ?, ?)", (user_id, identifier, encrypted_data))
    conn.commit()
    conn.close()

def get_account(user_id, identifier):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT data FROM accounts WHERE user_id = ? AND identifier = ?", (user_id, identifier))
    row = c.fetchone()
    conn.close()
    if row:
        return decrypt_data(row[0])
    return None

def list_accounts(user_id):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT identifier FROM accounts WHERE user_id = ?", (user_id,))
    rows = c.fetchall()
    conn.close()
    return [row[0] for row in rows]

def delete_account(user_id, identifier):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("DELETE FROM accounts WHERE user_id = ? AND identifier = ?", (user_id, identifier))
    conn.commit()
    conn.close()
    return c.rowcount

# Main program
def main():
    init_db()
    print("Chào mừng đến với bot lưu tài khoản!")

    user_id = None
    while not user_id:
        print("\n1. Đăng ký")
        print("2. Đăng nhập")
        choice = input("Lựa chọn: ")
        if choice == "1":
            username = input("Tên đăng nhập: ")
            password = input("Mật khẩu: ")
            register_user(username, password)
        elif choice == "2":
            username = input("Tên đăng nhập: ")
            password = input("Mật khẩu: ")
            user_id = login_user(username, password)

    while True:
        print("\n1. Thêm tài khoản")
        print("2. Lấy tài khoản")
        print("3. Liệt kê tài khoản")
        print("4. Xóa tài khoản")
        print("5. Thoát")
        choice = input("Lựa chọn: ")

        if choice == "1":
            identifier = input("Tên lưu: ")
            account_data = input("Nhập tài khoản|mật khẩu: ")
            add_account(user_id, identifier, account_data)
            print("Tài khoản đã được lưu!")
        elif choice == "2":
            identifier = input("Tên đã lưu: ")
            account_data = get_account(user_id, identifier)
            if account_data:
                print(f"Thông tin tài khoản: {account_data}")
            else:
                print("Không tìm thấy tài khoản.")
        elif choice == "3":
            accounts = list_accounts(user_id)
            if accounts:
                print("Danh sách tài khoản đã lưu:")
                for i, account in enumerate(accounts, start=1):
                    print(f"{i}. {account}")
            else:
                print("Chưa có tài khoản nào được lưu.")
        elif choice == "4":
            identifier = input("Tên tài khoản muốn xóa: ")
            deleted_rows = delete_account(user_id, identifier)
            if deleted_rows > 0:
                print("Tài khoản đã được xóa!")
            else:
                print("Không tìm thấy tài khoản để xóa.")
        elif choice == "5":
            print("Xin chào!")
            break
        else:
            print("Lựa chọn không hợp lệ, vui lòng thử lại.")

if __name__ == "__main__":
    key = load_key()
    cipher = Fernet(key)
    main()
if __name__ == "__main__":
    key = load_key()
    cipher = Fernet(key)
    init_db()
    app.run(debug=True)
