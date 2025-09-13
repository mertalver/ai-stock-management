from flask import Flask, request, jsonify, session
import sys
import os
import psutil
import json
import hashlib
import shutil
from datetime import datetime

# Add shared module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.database import get_db
from shared.logger import log_system

app = Flask(__name__)
app.secret_key = 'admin-service-secret-key'
DATABASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'stok_db.sqlite')

def hash_password(password):
    """Şifreyi hash'le"""
    return hashlib.sha256(password.encode()).hexdigest()

def log_activity(admin_id, action, description=None, level='INFO'):
    """Kullanıcı aktivitelerini logla"""
    try:
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None

        with get_db() as conn:
            conn.execute('''
                INSERT INTO activity_logs (admin_id, action, description, ip_address, user_agent, level)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (admin_id, action, description, ip_address, user_agent, level))
    except Exception as e:
        print(f"Log hatası: {e}")

@app.route('/products/all', methods=['GET'])
def api_all_products():
    """Tüm ürünleri JSON olarak döndürür (admin için)"""
    with get_db() as conn:
        products = conn.execute('''
            SELECT p.id, p.name, p.stock, p.critical_level, 
                   (p.stock < p.critical_level) as is_critical,
                   u.username
            FROM products p
            JOIN users u ON p.user_id = u.id
            ORDER BY u.username, p.name
        ''').fetchall()
    
    products_list = [{'id': p['id'], 'name': p['name'], 'stock': p['stock'], 'critical_level': p['critical_level'], 'is_critical': bool(p['is_critical']), 'username': p['username']} for p in products]
    
    return jsonify(products_list)

@app.route('/maintenance/system-stats', methods=['GET'])
def api_system_stats():
    """Sistem istatistikleri"""
    with get_db() as conn:
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        total_products = conn.execute('SELECT COUNT(*) as count FROM products').fetchone()['count']
        critical_products = conn.execute('SELECT COUNT(*) as count FROM products WHERE stock < critical_level').fetchone()['count']
        recent_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE created_at > datetime("now", "-1 day")').fetchone()['count']
        top_users = conn.execute('''
            SELECT u.username, COUNT(p.id) as product_count 
            FROM users u 
            LEFT JOIN products p ON u.id = p.user_id 
            GROUP BY u.id 
            ORDER BY product_count DESC 
            LIMIT 5
        ''').fetchall()
        categories = {
            'Kritik Stok': critical_products,
            'Normal Stok': total_products - critical_products,
            'Yeni Kullanıcılar': recent_users
        }
    db_size = os.path.getsize(DATABASE) if os.path.exists(DATABASE) else 0
    return jsonify({
        'total_users': total_users, 'total_products': total_products,
        'critical_products': critical_products, 'recent_users': recent_users,
        'top_users': [dict(user) for user in top_users], 'categories': categories,
        'db_size_bytes': db_size
    })

@app.route('/maintenance/users', methods=['GET'])
def api_users_list():
    """Tüm kullanıcıları listele"""
    with get_db() as conn:
        users = conn.execute('''
            SELECT u.id, u.username, u.email, u.created_at,
                   COUNT(p.id) as product_count,
                   COALESCE(SUM(p.stock), 0) as total_stock
            FROM users u
            LEFT JOIN products p ON u.id = p.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''').fetchall()
    return jsonify([dict(user) for user in users])

@app.route('/maintenance/users', methods=['POST'])
def api_add_user():
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')
    admin_id = data.get('admin_id')

    if not all([username, email, password, admin_id]):
        return jsonify({'error': 'Tüm alanlar zorunludur.'}), 400

    password_hash = hash_password(password)
    try:
        with get_db() as conn:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                         (username, email, password_hash))
        log_activity(admin_id, 'USER_CREATE_BY_ADMIN', f'Admin yeni kullanıcı oluşturdu: {username}')
        return jsonify({'success': True, 'message': 'Kullanıcı başarıyla oluşturuldu.'})
    except Exception as e:
        log_system('ERROR', f'Admin tarafından kullanıcı eklenirken hata: {e}', 'admin-service', 'api_add_user')
        return jsonify({'error': str(e)}), 500

@app.route('/maintenance/users/<int:user_id>', methods=['PUT'])
def api_update_user(user_id):
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')
    admin_id = data.get('admin_id')

    if not all([username, email, admin_id]):
        return jsonify({'error': 'Kullanıcı adı, e-posta ve admin ID zorunludur.'}), 400

    try:
        with get_db() as conn:
            if password:
                password_hash = hash_password(password)
                conn.execute('UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?',
                             (username, email, password_hash, user_id))
            else:
                conn.execute('UPDATE users SET username = ?, email = ? WHERE id = ?',
                             (username, email, user_id))
        log_activity(admin_id, 'USER_UPDATE_BY_ADMIN', f'Admin kullanıcıyı güncelledi: {username}')
        return jsonify({'success': True, 'message': 'Kullanıcı başarıyla güncellendi.'})
    except Exception as e:
        log_system('ERROR', f'Admin tarafından kullanıcı güncellenirken hata: {e}', 'admin-service', 'api_update_user')
        return jsonify({'error': str(e)}), 500

@app.route('/maintenance/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    data = request.get_json()
    admin_id = data.get('admin_id')
    if not admin_id:
        return jsonify({'error': 'Admin ID zorunludur.'}), 400
        
    with get_db() as conn:
        user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
        
        conn.execute('DELETE FROM products WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    log_activity(admin_id, 'USER_DELETE', f'Kullanıcı silindi: {user["username"]}')
    return jsonify({'success': True, 'message': 'Kullanıcı silindi'})

@app.route('/maintenance/analytics-data', methods=['GET'])
def api_analytics_data():
    with get_db() as conn:
        monthly_registrations = conn.execute('''
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
            FROM users GROUP BY month ORDER BY month DESC LIMIT 6
        ''').fetchall()
        popular_products = conn.execute('''
            SELECT name, COUNT(*) as count FROM products
            GROUP BY LOWER(name) ORDER BY count DESC LIMIT 10
        ''').fetchall()
        stock_distribution = conn.execute('''
            SELECT CASE 
                WHEN stock = 0 THEN 'Stok Yok'
                WHEN stock < critical_level THEN 'Kritik'
                WHEN stock < critical_level * 2 THEN 'Az'
                ELSE 'Yeterli'
            END as status, COUNT(*) as count FROM products GROUP BY status
        ''').fetchall()
        admin_count = conn.execute('SELECT COUNT(*) as count FROM admins').fetchone()['count']
        user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        user_role_distribution = {'Admin': admin_count, 'Kullanıcı': user_count}
        
    return jsonify({
        'monthly_registrations': [dict(row) for row in monthly_registrations],
        'popular_products': [dict(row) for row in popular_products],
        'stock_distribution': [dict(row) for row in stock_distribution],
        'user_role_distribution': user_role_distribution
    })

@app.route('/maintenance/settings', methods=['GET'])
def get_settings():
    try:
        with get_db() as conn:
            settings_rows = conn.execute('SELECT key, value FROM settings').fetchall()
            settings = {row['key']: row['value'] for row in settings_rows}
            return jsonify(settings)
    except Exception as e:
        log_system('ERROR', f'Ayarları getirme hatası: {str(e)}', 'get_settings')
        return jsonify({'error': str(e)}), 500

@app.route('/maintenance/settings', methods=['POST'])
def save_settings():
    data = request.get_json()
    admin_id = data.pop('admin_id', None)
    if not data or not admin_id:
        return jsonify({'error': 'Veri ve admin ID gerekli'}), 400
    try:
        with get_db() as conn:
            for key, value in data.items():
                conn.execute('UPDATE settings SET value = ? WHERE key = ?', (str(value), key))
        log_activity(admin_id, 'SETTINGS_UPDATED', f'Sistem ayarları güncellendi: {json.dumps(data)}')
        return jsonify({'success': True, 'message': 'Ayarlar başarıyla kaydedildi.'})
    except Exception as e:
        log_system('ERROR', f'Ayarları kaydetme hatası: {str(e)}', 'save_settings')
        return jsonify({'error': str(e)}), 500

@app.route('/maintenance/monitoring-data', methods=['GET'])
def api_monitoring_data():
    try:
        with get_db() as conn:
            active_users = conn.execute('''
                SELECT COUNT(DISTINCT user_id) as count 
                FROM activity_logs 
                WHERE timestamp > datetime('now', '-5 minutes') AND user_id IS NOT NULL
            ''').fetchone()['count']
            recent_logs = conn.execute('''
                SELECT al.action, al.timestamp, u.username, al.level
                FROM activity_logs al LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.timestamp DESC LIMIT 10
            ''').fetchall()
        
        return jsonify({
            'cpu': {'percent': psutil.cpu_percent(interval=1), 'count': psutil.cpu_count()},
            'memory': psutil.virtual_memory()._asdict(),
            'disk': psutil.disk_usage('/')._asdict(),
            'network': psutil.net_io_counters()._asdict(),
            'active_users': active_users,
            'recent_logs': [dict(log) for log in recent_logs]
        })
    except Exception as e:
        log_system('ERROR', f'İzleme verisi hatası: {str(e)}', 'api_monitoring_data')
        return jsonify({'error': 'İzleme verisi alınamadı'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5003) 