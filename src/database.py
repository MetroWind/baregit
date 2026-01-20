import sqlite3
import os
import secrets
from config import config

def getDbPath():
    data_path = config['paths']['data_path']
    return os.path.join(data_path, 'baregit.db')

def getDb():
    db_path = getDbPath()
    # Ensure directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def initDb():
    conn = getDb()
    cursor = conn.cursor()

    # Table: users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sub TEXT UNIQUE NOT NULL,
            preferred_username TEXT NOT NULL,
            git_password_hash TEXT,
            git_password_salt TEXT
        )
    ''')

    # Table: repos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    ''')

    # Table: system_config
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def getOrCreateSecretKey():
    conn = getDb()
    cursor = conn.cursor()
    
    cursor.execute("SELECT value FROM system_config WHERE key='flask_secret_key'")
    row = cursor.fetchone()
    
    if row:
        secret = row['value']
    else:
        secret = secrets.token_hex(32)
        cursor.execute("INSERT INTO system_config (key, value) VALUES (?, ?)", ('flask_secret_key', secret))
        conn.commit()
    
    conn.close()
    return secret
