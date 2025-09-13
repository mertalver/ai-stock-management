import sqlite3
import os

# Veritabanı dosyasının projenin kök dizininde olduğundan emin ol
DATABASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'stok_db.sqlite')

def get_db():
    """Veritabanı bağlantısı"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn 