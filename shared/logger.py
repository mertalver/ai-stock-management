from shared.database import get_db
from flask import request

def log_system(level, message, module=None, function_name=None, line_number=None):
    """Sistem loglarını kaydet"""
    try:
        with get_db() as conn:
            conn.execute('''
                INSERT INTO system_logs (level, message, module, function_name, line_number)
                VALUES (?, ?, ?, ?, ?)
            ''', (level, message, module, function_name, line_number))
    except Exception as e:
        print(f"Sistem log hatası: {e}")

def log_activity(action, description=None, level='INFO', user_id=None, admin_id=None):
    """Kullanıcı aktivitelerini logla"""
    try:
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None
        
        with get_db() as conn:
            conn.execute('''
                INSERT INTO activity_logs (user_id, admin_id, action, description, ip_address, user_agent, level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, admin_id, action, description, ip_address, user_agent, level))
    except Exception as e:
        print(f"Aktivite log hatası: {e}")

def log_stock_movement(user_id, product_id, product_name, movement_type, quantity_before, quantity_after, notes=None):
    """Stok hareketlerini kaydet"""
    try:
        quantity_change = quantity_after - quantity_before
        with get_db() as conn:
            conn.execute('''
                INSERT INTO stock_movements 
                (user_id, product_id, product_name, movement_type, quantity_before, quantity_after, quantity_change, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, product_id, product_name, movement_type, quantity_before, quantity_after, quantity_change, notes))
    except Exception as e:
        print(f"Stok hareket log hatası: {e}") 