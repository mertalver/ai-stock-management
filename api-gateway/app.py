from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash, g
import requests
import os
from functools import wraps
import logging
import psutil
import json
import sqlite3
import jwt
from werkzeug.security import generate_password_hash
import sys

# Add shared module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.logger import log_system, log_activity, log_stock_movement

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('API_GATEWAY_SECRET_KEY', 'default-gateway-secret-key')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default-jwt-secret-key')

# Microservice URLs from environment variables
USERS_SERVICE_URL = os.getenv("USERS_SERVICE_URL", "http://127.0.0.1:5001")
PRODUCTS_SERVICE_URL = os.getenv("PRODUCTS_SERVICE_URL", "http://127.0.0.1:5002")
ADMIN_SERVICE_URL = os.getenv("ADMIN_SERVICE_URL", "http://127.0.0.1:5003")
REPORTS_SERVICE_URL = os.getenv("REPORTS_SERVICE_URL", "http://127.0.0.1:5004")

DATABASE = os.getenv("DATABASE_PATH", "stok_db.sqlite")

def get_db():
    """Veritabanı bağlantısı"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Veritabanı tabloları oluştur"""
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                stock INTEGER NOT NULL DEFAULT 0,
                critical_level INTEGER NOT NULL DEFAULT 5,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                admin_id INTEGER,
                action TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT DEFAULT 'INFO'
            );
            
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                module TEXT,
                function_name TEXT,
                line_number INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS stock_movements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER,
                product_name TEXT NOT NULL,
                movement_type TEXT NOT NULL,
                quantity_before INTEGER,
                quantity_after INTEGER,
                quantity_change INTEGER NOT NULL,
                notes TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (product_id) REFERENCES products (id)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        ''')
        
        # Default admin'i daha güvenli bir parola ile oluşturun
        admin_hash = generate_password_hash('admin123')
        conn.execute('INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?, ?)', 
                    ('admin', admin_hash))

        # Default settings
        default_settings = {
            'site_title': 'Stok Yönetim Sistemi',
            'maintenance_mode': 'false',
            'allow_registration': 'true',
            'session_timeout': '30',
            'log_level': 'INFO'
        }
        for key, value in default_settings.items():
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))

def token_required(f):
    """Token gerektiren endpoint'ler için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
        
        if not token:
            token = request.cookies.get('token')

        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token bulunamadı'}), 401
            flash('Bu işlem için yetkiniz bulunmamaktadır, lütfen giriş yapın.', 'warning')
            return redirect(url_for('login'))

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            g.current_user = data
        except jwt.ExpiredSignatureError:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token süresi dolmuş'}), 401
            flash('Oturum süreniz doldu, lütfen tekrar giriş yapın.', 'warning')
            return redirect(url_for('login', next=request.url))
        except (jwt.InvalidTokenError, Exception) as e:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token geçersiz'}), 401
            flash('Geçersiz token, lütfen tekrar giriş yapın.', 'warning')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Admin gerektiren endpoint'ler için decorator"""
    @wraps(f)
    @token_required
    def decorated_function(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Bu işlem için admin yetkisi gerekmektedir.'}), 403
            flash('Bu sayfayı görüntülemek için admin yetkiniz bulunmamaktadır.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Context processor to make username available to all templates
@app.context_processor
def inject_user():
    user_info = {}
    if hasattr(g, 'current_user'):
        user_info['username'] = g.current_user.get('username') or g.current_user.get('admin_username')
        user_info['is_admin'] = g.current_user.get('role') == 'admin'
    return dict(user_info=user_info)

# Uygulama başlatıldığında veritabanını oluştur
with app.app_context():
    init_db()

# Ana sayfa routes
@app.route('/')
def index():
    """Ana giriş sayfası"""
    return render_template('index.html')

# Auth routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Kullanıcı kayıt"""
    if request.method == 'POST':
        payload = {"username": request.form.get('username'), "email": request.form.get('email'), "password": request.form.get('password')}
        try:
            response = requests.post(f"{USERS_SERVICE_URL}/register", json=payload)
            if response.status_code == 201:
                flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
                return redirect(url_for('login'))
            flash(response.json().get('error', 'Kayıt sırasında bir hata oluştu.'), 'error')
        except requests.exceptions.RequestException as e:
            flash(f'Auth servisine ulaşılamıyor: {e}', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Kullanıcı giriş"""
    if request.method == 'POST':
        payload = {"username": request.form.get('username'), "password": request.form.get('password')}
        try:
            response = requests.post(f"{USERS_SERVICE_URL}/login", json=payload)
            if response.status_code == 200:
                data = response.json()
                token = data.get('token')
                
                flash('Giriş başarılı!', 'success')
                # Token'ı tarayıcıda saklamak için bir sonraki sayfaya yönlendir ve token'ı cookie'ye ata
                resp = redirect(url_for('dashboard'))
                resp.set_cookie('token', token, httponly=True, samesite='Lax')
                return resp

            flash('Kullanıcı adı veya şifre hatalı.', 'error')
        except requests.exceptions.RequestException as e:
            flash(f'Auth servisine ulaşılamıyor: {e}', 'error')
    return render_template('login.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    """Admin giriş"""
    if request.method == 'POST':
        payload = {"username": request.form.get('username'), "password": request.form.get('password')}
        try:
            response = requests.post(f"{USERS_SERVICE_URL}/admin-login", json=payload)
            if response.status_code == 200:
                data = response.json()
                token = data.get('token')

                flash('Admin girişi başarılı!', 'success')
                resp = redirect(url_for('admin_panel'))
                resp.set_cookie('token', token, httponly=True, samesite='Lax')
                return resp
                
            flash('Admin kullanıcı adı veya şifre hatalı!', 'error')
        except requests.exceptions.RequestException as e:
            flash(f'Auth servisine ulaşılamıyor: {e}', 'error')
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    """Kullanıcı çıkış"""
    # Token cookie'sini silerek çıkış yap
    resp = redirect(url_for('index'))
    resp.delete_cookie('token')
    flash("Başarıyla çıkış yaptınız.", "success")
    return resp

# User dashboard
@app.route('/dashboard')
@token_required
def dashboard():
    """Kullanıcı dashboard"""
    return render_template('dashboard.html', username=g.current_user.get('username'))

@app.route('/reports')
@token_required
def user_reports():
    """Kullanıcı raporları"""
    return render_template('reports.html', username=g.current_user.get('username'))

@app.route('/llm-add-product')
@token_required
def llm_add_product():
    """LLM ile ürün ekleme sayfasını render eder"""
    return render_template('llm_add_product.html', username=g.current_user.get('username'))

@app.route('/profile')
@token_required
def profile():
    """Kullanıcı profili sayfası"""
    return render_template('profile.html', username=g.current_user.get('username'))

@app.route('/settings')
@token_required
def settings():
    """Kullanıcı ayarları sayfası"""
    return render_template('settings.html', username=g.current_user.get('username'))

# Admin panel
@app.route('/admin-panel')
@admin_required
def admin_panel():
    """Admin paneli"""
    return render_template('admin_panel.html', username=g.current_user.get('admin_username'))

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """Admin ayarları sayfası"""
    return render_template('admin/settings.html', username=g.current_user.get('admin_username'))

# Bakım Ekranları
@app.route('/maintenance')
@admin_required
def maintenance_dashboard():
    """Bakım ana dashboard"""
    return render_template('maintenance/dashboard.html', username=g.current_user.get('admin_username'))

@app.route('/maintenance/data')
@admin_required
def maintenance_data():
    """Veri yönetimi"""
    return render_template('maintenance/data.html', username=g.current_user.get('admin_username'))

@app.route('/maintenance/analytics')
@admin_required
def maintenance_analytics():
    """Analitik rapor"""
    return render_template('maintenance/analytics.html', username=g.current_user.get('admin_username'))

@app.route('/maintenance/settings')
@admin_required
def maintenance_settings():
    """Sistem ayarları"""
    return render_template('maintenance/settings.html', username=g.current_user.get('admin_username'))

@app.route('/admin/reports')
@admin_required
def admin_reports():
    """Admin raporları"""
    return render_template('admin_reports.html', username=g.current_user.get('admin_username'))

@app.route('/maintenance/logs')
@admin_required
def maintenance_logs():
    """Log görüntüleme"""
    return render_template('maintenance/logs.html', username=g.current_user.get('admin_username'))

@app.route('/maintenance/monitoring')
@admin_required
def maintenance_monitoring():
    """Sistem izleme"""
    return render_template('maintenance/monitoring.html', username=g.current_user.get('admin_username'))

# API Routes
@app.route('/api/my-products')
@token_required
def api_my_products():
    """Kullanıcının ürünlerini JSON olarak döndürür"""
    user_id = g.current_user.get('user_id')
    
    with get_db() as conn:
        products = conn.execute('''
            SELECT id, name, stock, critical_level, 
                   (stock < critical_level) as is_critical
            FROM products 
            WHERE user_id = ? 
            ORDER BY name
        ''', (user_id,)).fetchall()
    
    products_list = []
    for product in products:
        products_list.append({
            'id': product['id'],
            'name': product['name'],
            'stock': product['stock'],
            'critical_level': product['critical_level'],
            'is_critical': bool(product['is_critical'])
        })
    
    return jsonify(products_list)

@app.route('/api/all-products')
@admin_required
def api_all_products():
    """Tüm ürünleri JSON olarak döndürür (admin için)"""
    user_id = g.current_user.get('user_id')
    page = request.args.get('page', 1, type=int)
    
    with get_db() as conn:
        products = conn.execute('''
            SELECT p.id, p.name, p.stock, p.critical_level, 
                   (p.stock < p.critical_level) as is_critical,
                   u.username
            FROM products p
            JOIN users u ON p.user_id = u.id
            ORDER BY u.username, p.name
        ''').fetchall()
    
    products_list = []
    for product in products:
        products_list.append({
            'id': product['id'],
            'name': product['name'],
            'stock': product['stock'],
            'critical_level': product['critical_level'],
            'is_critical': bool(product['is_critical']),
            'username': product['username']
        })
    
    return jsonify(products_list)

@app.route('/api/add-product', methods=['POST'])
@token_required
def api_add_product():
    """Yeni ürün ekle"""
    data = request.get_json()
    user_id = g.current_user.get('user_id')
    
    name = data.get('name')
    stock = data.get('stock', 0)
    critical_level = data.get('critical_level', 5)
    
    if not name:
        return jsonify({'error': 'Ürün adı gerekli'}), 400
    
    try:
        with get_db() as conn:
            cursor = conn.execute('''
                INSERT INTO products (user_id, name, stock, critical_level)
                VALUES (?, ?, ?, ?)
            ''', (user_id, name, stock, critical_level))
            
            product_id = cursor.lastrowid
            
        # Stok hareketi kaydet
        log_stock_movement(user_id, product_id, name, 'ADD', 0, stock, 'Yeni ürün eklendi')
        log_activity('PRODUCT_ADD', f'Yeni ürün eklendi: {name}', user_id=user_id)
        
        return jsonify({
            'success': True,
            'id': product_id,
            'message': 'Ürün başarıyla eklendi'
        })
    except Exception as e:
        log_system('ERROR', f'Ürün ekleme hatası: {str(e)}', 'api_add_product')
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-product/<int:product_id>', methods=['PUT'])
@token_required
def api_update_product(product_id):
    """Ürün güncelle"""
    data = request.get_json()
    user_id = g.current_user.get('user_id')
    
    # Ürünün kullanıcıya ait olduğunu kontrol et
    with get_db() as conn:
        product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?',
                              (product_id, user_id)).fetchone()
        
        if not product:
            return jsonify({'error': 'Ürün bulunamadı'}), 404
        
        # Güncelleme
        name = data.get('name', product['name'])
        stock = data.get('stock', product['stock'])
        critical_level = data.get('critical_level', product['critical_level'])
        
        # Stok değişikliği var mı kontrol et
        stock_changed = stock != product['stock']
        old_stock = product['stock']
        
        conn.execute('''
            UPDATE products 
            SET name = ?, stock = ?, critical_level = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        ''', (name, stock, critical_level, product_id, user_id))
        
    # Stok değişikliği varsa hareket kaydet
    if stock_changed:
        movement_type = 'INCREASE' if stock > old_stock else 'DECREASE'
        notes = f'Stok güncellendi: {old_stock} → {stock}'
        log_stock_movement(user_id, product_id, name, movement_type, old_stock, stock, notes)
    
    log_activity('PRODUCT_UPDATE', f'Ürün güncellendi: {name}', user_id=user_id)
    
    return jsonify({'success': True, 'message': 'Ürün güncellendi'})

@app.route('/api/delete-product/<int:product_id>', methods=['DELETE'])
@token_required
def api_delete_product(product_id):
    """Ürün sil"""
    user_id = g.current_user.get('user_id')
    
    with get_db() as conn:
        # Önce ürün bilgilerini al
        product = conn.execute('SELECT name, stock FROM products WHERE id = ? AND user_id = ?',
                              (product_id, user_id)).fetchone()
        
        if not product:
            return jsonify({'error': 'Ürün bulunamadı'}), 404
        
        # Stok hareketi kaydet (silme işlemi)
        log_stock_movement(user_id, product_id, product['name'], 'DELETE', product['stock'], 0, 'Ürün silindi')
        
        result = conn.execute('DELETE FROM products WHERE id = ? AND user_id = ?',
                             (product_id, user_id))
        
        if result.rowcount == 0:
            return jsonify({'error': 'Ürün bulunamadı'}), 404
    
    log_activity('PRODUCT_DELETE', f'Ürün silindi: {product["name"]}', user_id=user_id)
    
    return jsonify({'success': True, 'message': 'Ürün silindi'})

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    """Kullanıcı profil bilgilerini getirir"""
    user_id = g.current_user.get('user_id')
    with get_db() as conn:
        user = conn.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
    return jsonify(dict(user))

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile():
    """Kullanıcı profilini günceller"""
    user_id = g.current_user.get('user_id')
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not username or not email:
        return jsonify({'error': 'Kullanıcı adı ve e-posta zorunludur.'}), 400
    
    try:
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            
            # If user wants to change password
            if new_password:
                if not current_password:
                    return jsonify({'error': 'Şifre değişikliği için mevcut şifrenizi girmelisiniz.'}), 400
                
                if generate_password_hash(current_password) != user['password_hash']:
                    return jsonify({'error': 'Mevcut şifreniz yanlış.'}), 403
                
                # Update with new password
                password_hash = generate_password_hash(new_password)
                conn.execute(
                    'UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?',
                    (username, email, password_hash, user_id)
                )
            else:
                # Update without changing password
                conn.execute(
                    'UPDATE users SET username = ?, email = ? WHERE id = ?',
                    (username, email, user_id)
                )

            # Update session username if it changed
            if session.get('username') != username:
                session['username'] = username

            log_activity('USER_PROFILE_UPDATE', f'Kullanıcı profilini güncelledi: {username}', user_id=user_id)
            return jsonify({'success': True, 'message': 'Profil başarıyla güncellendi.'})
            
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Bu kullanıcı adı veya e-posta başka bir kullanıcı tarafından kullanılıyor.'}), 409
    except Exception as e:
        log_system('ERROR', f'Profil güncellenirken hata: {e}', 'update_profile')
        return jsonify({'error': str(e)}), 500

@app.route('/api/import-stock', methods=['POST'])
@token_required
def import_stock():
    """CSV dosyasından stok verilerini içe aktarır."""
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya bulunamadı.'}), 400

    user_id = g.current_user.get('user_id')
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Dosya seçilmedi.'}), 400

    if file and file.filename.endswith('.csv'):
        try:
            import csv
            import io

            stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
            csv_reader = csv.reader(stream)
            
            # Başlık satırını atla (varsa)
            next(csv_reader, None)
            
            updated_count = 0
            added_count = 0
            
            with get_db() as conn:
                for row in csv_reader:
                    if len(row) < 2:
                        continue
                    
                    product_name = row[0].strip()
                    quantity_change = int(row[1].strip())
                    
                    # Ürün veritabanında var mı diye kontrol et
                    product = conn.execute('SELECT id, stock, name FROM products WHERE user_id = ? AND LOWER(name) = ?', 
                                           (user_id, product_name.lower())).fetchone()
                    
                    if product:
                        # Ürün varsa stoğu güncelle
                        old_stock = product['stock']
                        new_stock = old_stock + quantity_change
                        conn.execute('UPDATE products SET stock = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (new_stock, product['id']))
                        log_stock_movement(user_id, product['id'], product['name'], 'IMPORT', old_stock, new_stock, f'CSV Import: {quantity_change}')
                        updated_count += 1
                    else:
                        # Ürün yoksa yeni ürün olarak ekle (kritik seviye varsayılan)
                        cursor = conn.execute('INSERT INTO products (user_id, name, stock) VALUES (?, ?, ?)', (user_id, product_name, quantity_change))
                        product_id = cursor.lastrowid
                        log_stock_movement(user_id, product_id, product_name, 'IMPORT_ADD', 0, quantity_change, f'CSV Import: Yeni ürün eklendi')
                        added_count += 1
            
            message = f"{updated_count} ürün güncellendi, {added_count} yeni ürün eklendi."
            log_activity('STOCK_IMPORT', message, user_id=user_id)
            return jsonify({'success': True, 'message': message})

        except Exception as e:
            log_system('ERROR', f'CSV import hatası: {e}', 'import_stock')
            return jsonify({'error': f'Dosya işlenirken bir hata oluştu: {e}'}), 500

    return jsonify({'error': 'Geçersiz dosya formatı. Lütfen .csv dosyası yükleyin.'}), 400

@app.route('/api/llm-add-products', methods=['POST'])
@token_required
def api_llm_add_products():
    """LLM chat'inden gelen isteği alır ve users-servisine yönlendirir"""
    data = request.get_json()
    user_id = g.current_user.get('user_id')
    prompt = data.get('prompt')

    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400

    payload = {
        'user_id': user_id,
        'prompt': prompt
    }
    
    try:
        # Set a longer timeout for the LLM service
        response = requests.post(f'{USERS_SERVICE_URL}/llm-process-prompt', json=payload, timeout=120)
        print(response.content)
        # Pass through the content, status code, and headers from the microservice
        return response.content, response.status_code, dict(response.headers)
    except requests.exceptions.Timeout:
        log_system('ERROR', 'Request to users-service timed out', 'api-gateway', 'api_llm_add_products')
        return jsonify({'error': 'The request to the AI service timed out. Please try again.'}), 504
    except requests.exceptions.RequestException as e:
        log_system('ERROR', f'Error connecting to users-service: {e}', 'api-gateway', 'api_llm_add_products')
        return jsonify({'error': 'Could not connect to the user service.'}), 503

# Bakım API'leri
@app.route('/api/maintenance/system-stats')
@admin_required
def api_system_stats():
    """Sistem istatistikleri"""
    with get_db() as conn:
        # Kullanıcı istatistikleri
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        total_products = conn.execute('SELECT COUNT(*) as count FROM products').fetchone()['count']
        critical_products = conn.execute('SELECT COUNT(*) as count FROM products WHERE stock < critical_level').fetchone()['count']
        
        # Son aktiviteler (son 24 saat)
        recent_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE created_at > datetime("now", "-1 day")').fetchone()['count']
        
        # En aktif kullanıcılar
        top_users = conn.execute('''
            SELECT u.username, COUNT(p.id) as product_count 
            FROM users u 
            LEFT JOIN products p ON u.id = p.user_id 
            GROUP BY u.id 
            ORDER BY product_count DESC 
            LIMIT 5
        ''').fetchall()
        
        # Kategoriler (örnek)
        categories = {
            'Kritik Stok': critical_products,
            'Normal Stok': total_products - critical_products,
            'Yeni Kullanıcılar': recent_users
        }
        
    db_size = os.path.getsize(DATABASE) if os.path.exists(DATABASE) else 0
        
    return jsonify({
        'total_users': total_users,
        'total_products': total_products,
        'critical_products': critical_products,
        'recent_users': recent_users,
        'top_users': [dict(user) for user in top_users],
        'categories': categories,
        'db_size_bytes': db_size
    })

@app.route('/api/maintenance/users-list')
@admin_required
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

@app.route('/api/maintenance/users', methods=['POST'])
@admin_required
def api_add_user():
    """Yeni kullanıcı ekler (admin tarafından)."""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'error': 'Tüm alanlar zorunludur.'}), 400

    password_hash = generate_password_hash(password)
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
        log_activity('USER_CREATE_BY_ADMIN', f'Admin yeni kullanıcı oluşturdu: {username}', admin_id=g.current_user.get('admin_id'))
        return jsonify({'success': True, 'message': 'Kullanıcı başarıyla oluşturuldu.'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Bu kullanıcı adı veya e-posta zaten mevcut.'}), 409
    except Exception as e:
        log_system('ERROR', f'Admin tarafından kullanıcı eklenirken hata: {e}', 'api_add_user')
        return jsonify({'error': str(e)}), 500

@app.route('/api/maintenance/users/<int:user_id>', methods=['PUT'])
@admin_required
def api_update_user(user_id):
    """Kullanıcı bilgilerini günceller (admin tarafından)."""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password') # Şifre isteğe bağlı

    if not username or not email:
        return jsonify({'error': 'Kullanıcı adı ve e-posta zorunludur.'}), 400

    try:
        with get_db() as conn:
            if password:
                # Eğer yeni bir şifre girildiyse, hash'le ve güncelle
                password_hash = generate_password_hash(password)
                conn.execute(
                    'UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?',
                    (username, email, password_hash, user_id)
                )
            else:
                # Şifre girilmediyse, mevcut şifreyi koru
                conn.execute(
                    'UPDATE users SET username = ?, email = ? WHERE id = ?',
                    (username, email, user_id)
                )
        log_activity('USER_UPDATE_BY_ADMIN', f'Admin kullanıcıyı güncelledi: {username}', admin_id=g.current_user.get('admin_id'))
        return jsonify({'success': True, 'message': 'Kullanıcı başarıyla güncellendi.'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Bu kullanıcı adı veya e-posta başka bir kullanıcı tarafından kullanılıyor.'}), 409
    except Exception as e:
        log_system('ERROR', f'Admin tarafından kullanıcı güncellenirken hata: {e}', 'api_update_user')
        return jsonify({'error': str(e)}), 500

@app.route('/api/maintenance/delete-user/<int:user_id>', methods=['DELETE'])
@admin_required
def api_delete_user(user_id):
    """Kullanıcı sil"""
    with get_db() as conn:
        # Önce kullanıcı adını al
        user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
        
        # Önce kullanıcının ürünlerini sil
        conn.execute('DELETE FROM products WHERE user_id = ?', (user_id,))
        # Sonra kullanıcıyı sil
        result = conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        if result.rowcount == 0:
            return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
    
    log_activity('USER_DELETE', f'Kullanıcı silindi: {user["username"]}', admin_id=g.current_user.get('admin_id'))
    
    return jsonify({'success': True, 'message': 'Kullanıcı silindi'})

@app.route('/api/maintenance/analytics-data')
@admin_required
def api_analytics_data():
    """Analitik veri"""
    with get_db() as conn:
        # Aylık kullanıcı kayıtları
        monthly_registrations = conn.execute('''
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
            FROM users
            GROUP BY month
            ORDER BY month DESC
            LIMIT 6
        ''').fetchall()
        
        # En popüler ürünler
        popular_products = conn.execute('''
            SELECT name, COUNT(*) as count
            FROM products
            GROUP BY LOWER(name)
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()
        
        # Stok durumu dağılımı
        stock_distribution = conn.execute('''
            SELECT 
                CASE 
                    WHEN stock = 0 THEN 'Stok Yok'
                    WHEN stock < critical_level THEN 'Kritik'
                    WHEN stock < critical_level * 2 THEN 'Az'
                    ELSE 'Yeterli'
                END as status,
                COUNT(*) as count
            FROM products
            GROUP BY status
        ''').fetchall()

        # Kullanıcı rol dağılımı
        admin_count = conn.execute('SELECT COUNT(*) as count FROM admins').fetchone()['count']
        user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        user_role_distribution = {
            'Admin': admin_count,
            'Kullanıcı': user_count
        }
        
    return jsonify({
        'monthly_registrations': [dict(row) for row in monthly_registrations],
        'popular_products': [dict(row) for row in popular_products],
        'stock_distribution': [dict(row) for row in stock_distribution],
        'user_role_distribution': user_role_distribution
    })

@app.route('/api/maintenance/backups')
@admin_required
def api_list_backups():
    """Mevcut yedek dosyalarını listeler."""
    backup_dir = os.getenv("BACKUP_PATH", "backups")
    if not os.path.exists(backup_dir):
        return jsonify([]) # Klasör yoksa boş liste döndür
    try:
        backups = sorted(
            [f for f in os.listdir(backup_dir) if f.endswith('.db')],
            key=lambda f: os.path.getmtime(os.path.join(backup_dir, f)),
            reverse=True
        )
        return jsonify(backups)
    except Exception as e:
        log_system('ERROR', f'Yedekleri listeleme hatası: {str(e)}', 'api_list_backups')
        return jsonify({'error': str(e)}), 500

@app.route('/api/maintenance/backup', methods=['POST'])
@admin_required
def api_create_backup():
    """Veritabanı backup oluştur"""
    import shutil
    from datetime import datetime
    
    try:
        backup_dir = os.getenv("BACKUP_PATH", "backups")
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(DATABASE, os.path.join(backup_dir, backup_name))
        
        log_activity('BACKUP_CREATE', f'Yeni veritabanı yedeği oluşturuldu: {backup_name}', admin_id=g.current_user.get('admin_id'))

        return jsonify({
            'success': True, 
            'message': f'Backup oluşturuldu: {backup_name}',
            'filename': backup_name
        })
    except Exception as e:
        log_system('ERROR', f'Backup hatası: {str(e)}', 'api_create_backup')
        return jsonify({'error': f'Backup hatası: {str(e)}'}), 500

@app.route('/api/maintenance/clear-old-data', methods=['POST'])
@admin_required
def api_clear_old_data():
    """Eski verileri temizle"""
    days = request.json.get('days', 30)
    try:
        with get_db() as conn:
            # 30 günden eski kayıtları sil (örnek)
            result = conn.execute('''
                DELETE FROM products 
                WHERE updated_at < datetime('now', '-{} days') 
                AND stock = 0
            '''.format(days))
            
        log_activity('DATA_CLEANUP', f'{result.rowcount} eski kayıt silindi.', admin_id=g.current_user.get('admin_id'))

        return jsonify({
            'success': True,
            'message': f'{result.rowcount} eski kayıt silindi'
        })
    except Exception as e:
        log_system('ERROR', f'Temizleme hatası: {str(e)}', 'api_clear_old_data')
        return jsonify({'error': f'Temizleme hatası: {str(e)}'}), 500

# Ayarlar API'leri
@app.route('/api/maintenance/settings', methods=['GET'])
@admin_required
def get_settings():
    """Tüm ayarları getir"""
    try:
        with get_db() as conn:
            settings_rows = conn.execute('SELECT key, value FROM settings').fetchall()
            settings = {row['key']: row['value'] for row in settings_rows}
            return jsonify(settings)
    except Exception as e:
        log_system('ERROR', f'Ayarları getirme hatası: {str(e)}', 'get_settings')
        return jsonify({'error': str(e)}), 500

@app.route('/api/maintenance/settings', methods=['POST'])
@admin_required
def save_settings():
    """Ayarları kaydet"""
    settings_data = request.json
    if not settings_data:
        return jsonify({'error': 'Veri yok'}), 400
    try:
        with get_db() as conn:
            for key, value in settings_data.items():
                conn.execute('UPDATE settings SET value = ? WHERE key = ?', (str(value), key))
        log_activity('SETTINGS_UPDATED', f'Sistem ayarları güncellendi: {json.dumps(settings_data)}', admin_id=g.current_user.get('admin_id'))
        return jsonify({'success': True, 'message': 'Ayarlar başarıyla kaydedildi.'})
    except Exception as e:
        log_system('ERROR', f'Ayarları kaydetme hatası: {str(e)}', 'save_settings')
        return jsonify({'error': str(e)}), 500

# Log ve İzleme API'leri
@app.route('/api/maintenance/activity-logs')
@admin_required
def api_activity_logs():
    """Aktivite logları"""
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    level = request.args.get('level', None)
    search = request.args.get('search', None)
    
    offset = (page - 1) * limit
    
    query = '''
        SELECT al.*, u.username as user_name, a.username as admin_name
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        LEFT JOIN admins a ON al.admin_id = a.id
    '''
    params = []
    
    conditions = []
    if level:
        conditions.append('al.level = ?')
        params.append(level)
    
    if search:
        conditions.append('(al.action LIKE ? OR al.description LIKE ?)')
        params.extend([f'%{search}%', f'%{search}%'])
    
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    
    query += ' ORDER BY al.timestamp DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    with get_db() as conn:
        logs = conn.execute(query, params).fetchall()
        
        # Toplam sayı
        count_query = 'SELECT COUNT(*) as count FROM activity_logs al'
        if conditions:
            count_query += ' WHERE ' + ' AND '.join(conditions)
        total = conn.execute(count_query, params[:-2]).fetchone()['count']
    
    return jsonify({
        'logs': [dict(log) for log in logs],
        'total': total,
        'page': page,
        'pages': (total + limit - 1) // limit
    })

@app.route('/api/maintenance/system-logs')
@admin_required
def api_system_logs():
    """Sistem logları"""
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    level = request.args.get('level', None)
    
    offset = (page - 1) * limit
    
    query = 'SELECT * FROM system_logs'
    params = []
    
    if level:
        query += ' WHERE level = ?'
        params.append(level)
    
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    with get_db() as conn:
        logs = conn.execute(query, params).fetchall()
        
        # Toplam sayı
        count_query = 'SELECT COUNT(*) as count FROM system_logs'
        if level:
            count_query += ' WHERE level = ?'
        total = conn.execute(count_query, params[:-2] if level else []).fetchone()['count']
    
    return jsonify({
        'logs': [dict(log) for log in logs],
        'total': total,
        'page': page,
        'pages': (total + limit - 1) // limit
    })

@app.route('/api/maintenance/monitoring-data')
@admin_required
def api_monitoring_data():
    """İzleme verileri"""
    try:
        # CPU kullanımı
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # RAM kullanımı
        memory = psutil.virtual_memory()
        
        # Disk kullanımı
        disk = psutil.disk_usage('/')
        
        # Network istatistikleri
        network = psutil.net_io_counters()
        
        # Aktif kullanıcılar (son 5 dakika)
        with get_db() as conn:
            active_users = conn.execute('''
                SELECT COUNT(DISTINCT user_id) as count 
                FROM activity_logs 
                WHERE timestamp > datetime('now', '-5 minutes')
                AND user_id IS NOT NULL
            ''').fetchone()['count']
            
            # Son loglar
            recent_logs = conn.execute('''
                SELECT al.action, al.timestamp, u.username, al.level
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.timestamp DESC
                LIMIT 10
            ''').fetchall()
        
        return jsonify({
            'cpu': {
                'percent': cpu_percent,
                'count': psutil.cpu_count()
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': (disk.used / disk.total) * 100
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'active_users': active_users,
            'recent_logs': [dict(log) for log in recent_logs]
        })
    except Exception as e:
        log_system('ERROR', f'İzleme verisi hatası: {str(e)}', 'api_monitoring_data')
        return jsonify({'error': 'İzleme verisi alınamadı'}), 500

@app.route('/api/maintenance/clear-logs', methods=['POST'])
@admin_required
def api_clear_logs():
    """Logları temizle"""
    data = request.get_json()
    log_type = data.get('type', 'activity')  # 'activity' veya 'system'
    days = data.get('days', 30)
    
    try:
        with get_db() as conn:
            if log_type == 'activity':
                result = conn.execute('''
                    DELETE FROM activity_logs 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                log_activity('LOGS_CLEARED', f'Aktivite logları temizlendi ({days} gün öncesi)', admin_id=g.current_user.get('admin_id'))
            else:
                result = conn.execute('''
                    DELETE FROM system_logs 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                log_activity('LOGS_CLEARED', f'Sistem logları temizlendi ({days} gün öncesi)', admin_id=g.current_user.get('admin_id'))
        
        return jsonify({
            'success': True,
            'message': f'{result.rowcount} log kaydı silindi'
        })
    except Exception as e:
        log_system('ERROR', f'Log temizleme hatası: {str(e)}', 'api_clear_logs')
        return jsonify({'error': f'Log temizleme hatası: {str(e)}'}), 500

# Raporlama API'leri
@app.route('/api/reports/stock-movements')
@token_required
def api_user_stock_movements():
    """Kullanıcının stok hareketleri"""
    user_id = g.current_user.get('user_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    movement_type = request.args.get('movement_type')
    source = request.args.get('source')
    
    query = '''
        SELECT sm.*, p.name as current_product_name
        FROM stock_movements sm
        LEFT JOIN products p ON sm.product_id = p.id
        WHERE sm.user_id = ?
    '''
    params = [user_id]
    
    if start_date:
        query += ' AND DATE(sm.timestamp) >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND DATE(sm.timestamp) <= ?'
        params.append(end_date)
    
    if movement_type:
        query += ' AND sm.movement_type = ?'
        params.append(movement_type)
    
    if source == 'llm':
        query += " AND sm.notes LIKE 'LLM%'"
    elif source == 'user':
        query += " AND (sm.notes NOT LIKE 'LLM%' OR sm.notes IS NULL)"
    
    query += ' ORDER BY sm.timestamp DESC'
    
    with get_db() as conn:
        movements = conn.execute(query, params).fetchall()
        
        # İstatistikler
        stats_query = '''
            SELECT 
                movement_type,
                COUNT(*) as count,
                SUM(ABS(quantity_change)) as total_quantity
            FROM stock_movements 
            WHERE user_id = ?
        '''
        stats_params = [user_id]
        
        if start_date:
            stats_query += ' AND DATE(timestamp) >= ?'
            stats_params.append(start_date)
        
        if end_date:
            stats_query += ' AND DATE(timestamp) <= ?'
            stats_params.append(end_date)

        if source == 'llm':
            stats_query += " AND notes LIKE 'LLM%'"
        elif source == 'user':
            stats_query += " AND (notes NOT LIKE 'LLM%' OR notes IS NULL)"
        
        stats_query += ' GROUP BY movement_type'
        
        stats = conn.execute(stats_query, stats_params).fetchall()
    
    return jsonify({
        'movements': [dict(movement) for movement in movements],
        'statistics': [dict(stat) for stat in stats]
    })

@app.route('/api/reports/admin-stock-movements')
@admin_required
def api_admin_stock_movements():
    """Admin tüm stok hareketleri"""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    movement_type = request.args.get('movement_type')
    username = request.args.get('username')
    source = request.args.get('source')
    
    query = '''
        SELECT sm.*, u.username, p.name as current_product_name
        FROM stock_movements sm
        JOIN users u ON sm.user_id = u.id
        LEFT JOIN products p ON sm.product_id = p.id
        WHERE 1=1
    '''
    params = []
    
    if start_date:
        query += ' AND DATE(sm.timestamp) >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND DATE(sm.timestamp) <= ?'
        params.append(end_date)
    
    if movement_type:
        query += ' AND sm.movement_type = ?'
        params.append(movement_type)
    
    if username:
        query += ' AND u.username LIKE ?'
        params.append(f'%{username}%')
    
    if source == 'llm':
        query += " AND sm.notes LIKE 'LLM%'"
    elif source == 'user':
        query += " AND (sm.notes NOT LIKE 'LLM%' OR sm.notes IS NULL)"
    
    query += ' ORDER BY sm.timestamp DESC'
    
    with get_db() as conn:
        movements = conn.execute(query, params).fetchall()
        
        # Genel istatistikler
        stats_query = '''
            SELECT 
                movement_type,
                COUNT(*) as count,
                SUM(ABS(quantity_change)) as total_quantity
            FROM stock_movements sm
            JOIN users u ON sm.user_id = u.id
            WHERE 1=1
        '''
        stats_params = []
        
        if start_date:
            stats_query += ' AND DATE(sm.timestamp) >= ?'
            stats_params.append(start_date)
        
        if end_date:
            stats_query += ' AND DATE(sm.timestamp) <= ?'
            stats_params.append(end_date)
        
        if username:
            stats_query += ' AND u.username LIKE ?'
            stats_params.append(f'%{username}%')
        
        if source == 'llm':
            stats_query += " AND sm.notes LIKE 'LLM%'"
        elif source == 'user':
            stats_query += " AND (sm.notes NOT LIKE 'LLM%' OR sm.notes IS NULL)"
        
        stats_query += ' GROUP BY movement_type'
        
        stats = conn.execute(stats_query, stats_params).fetchall()
        
        # Kullanıcı bazında istatistikler
        user_stats_query = '''
            SELECT 
                u.username,
                COUNT(*) as total_movements,
                SUM(CASE WHEN sm.movement_type = 'ADD' THEN 1 ELSE 0 END) as additions,
                SUM(CASE WHEN sm.movement_type = 'INCREASE' THEN 1 ELSE 0 END) as increases,
                SUM(CASE WHEN sm.movement_type = 'DECREASE' THEN 1 ELSE 0 END) as decreases,
                SUM(CASE WHEN sm.movement_type = 'DELETE' THEN 1 ELSE 0 END) as deletions
            FROM stock_movements sm
            JOIN users u ON sm.user_id = u.id
            WHERE 1=1
        '''
        user_stats_params = []
        
        if start_date:
            user_stats_query += ' AND DATE(sm.timestamp) >= ?'
            user_stats_params.append(start_date)
        
        if end_date:
            user_stats_query += ' AND DATE(sm.timestamp) <= ?'
            user_stats_params.append(end_date)
        
        if username:
            user_stats_query += ' AND u.username LIKE ?'
            user_stats_params.append(f'%{username}%')
        
        if source == 'llm':
            user_stats_query += " AND sm.notes LIKE 'LLM%'"
        elif source == 'user':
            user_stats_query += " AND (sm.notes NOT LIKE 'LLM%' OR sm.notes IS NULL)"
        
        user_stats_query += ' GROUP BY u.id, u.username ORDER BY total_movements DESC'
        
        user_stats = conn.execute(user_stats_query, user_stats_params).fetchall()
    
    return jsonify({
        'movements': [dict(movement) for movement in movements],
        'statistics': [dict(stat) for stat in stats],
        'user_statistics': [dict(stat) for stat in user_stats]
    })

@app.route('/api/reports/summary')
@token_required
def api_user_reports_summary():
    """Kullanıcı rapor özeti"""
    user_id = g.current_user.get('user_id')
    
    with get_db() as conn:
        # Toplam ürün sayısı
        total_products = conn.execute('SELECT COUNT(*) as count FROM products WHERE user_id = ?', (user_id,)).fetchone()['count']
        
        # Kritik stok sayısı
        critical_products = conn.execute('''
            SELECT COUNT(*) as count FROM products 
            WHERE user_id = ? AND stock < critical_level
        ''', (user_id,)).fetchone()['count']
        
        # Toplam stok değeri (adet)
        total_stock = conn.execute('SELECT SUM(stock) as total FROM products WHERE user_id = ?', (user_id,)).fetchone()['total'] or 0
        
        # Son 30 günde hareketler
        recent_movements = conn.execute('''
            SELECT COUNT(*) as count FROM stock_movements 
            WHERE user_id = ? AND timestamp > datetime('now', '-30 days')
        ''', (user_id,)).fetchone()['count']
        
        # En çok hareket eden ürünler
        top_products = conn.execute('''
            SELECT product_name, COUNT(*) as movement_count
            FROM stock_movements 
            WHERE user_id = ?
            GROUP BY product_name
            ORDER BY movement_count DESC
            LIMIT 5
        ''', (user_id,)).fetchall()
        
        # Aylık hareket trendi
        monthly_trend = conn.execute('''
            SELECT 
                strftime('%Y-%m', timestamp) as month,
                COUNT(*) as count
            FROM stock_movements 
            WHERE user_id = ?
            GROUP BY month
            ORDER BY month DESC
            LIMIT 6
        ''', (user_id,)).fetchall()
    
    return jsonify({
        'total_products': total_products,
        'critical_products': critical_products,
        'total_stock': total_stock,
        'recent_movements': recent_movements,
        'top_products': [dict(product) for product in top_products],
        'monthly_trend': [dict(trend) for trend in monthly_trend]
    })

@app.route('/api/reports/admin-summary')
@admin_required
def api_admin_reports_summary():
    """Admin rapor özeti"""
    with get_db() as conn:
        # Genel istatistikler
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        total_products = conn.execute('SELECT COUNT(*) as count FROM products').fetchone()['count']
        total_movements = conn.execute('SELECT COUNT(*) as count FROM stock_movements').fetchone()['count']
        
        # En aktif kullanıcılar
        top_users = conn.execute('''
            SELECT 
                u.username,
                COUNT(sm.id) as movement_count,
                COUNT(DISTINCT sm.product_id) as product_count
            FROM users u
            LEFT JOIN stock_movements sm ON u.id = sm.user_id
            GROUP BY u.id, u.username
            ORDER BY movement_count DESC
            LIMIT 5
        ''').fetchall()
        
        # Günlük aktivite trendi
        daily_trend = conn.execute('''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as count
            FROM stock_movements
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY date
            ORDER BY date
        ''').fetchall()
        
        # Hareket tipi dağılımı
        movement_distribution = conn.execute('''
            SELECT 
                movement_type,
                COUNT(*) as count
            FROM stock_movements
            GROUP BY movement_type
        ''').fetchall()
    
    return jsonify({
        'total_users': total_users,
        'total_products': total_products,
        'total_movements': total_movements,
        'top_users': [dict(user) for user in top_users],
        'daily_trend': [dict(trend) for trend in daily_trend],
        'movement_distribution': [dict(dist) for dist in movement_distribution]
    })

# --- API Gateway Routes ---
def forward_request(service_url, path, method, data=None, json_payload=None, params=None, files=None):
    try:
        url = f"{service_url}/{path}"
        headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'content-length']}
        
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_payload,
            data=data,
            files=files,
            cookies=request.cookies,
            timeout=5 # Add a timeout for service calls
        )
        
        # Forward the response from the microservice
        response_headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']]
        return resp.content, resp.status_code, response_headers

    except requests.exceptions.RequestException as e:
        error_message = {'error': 'Service unavailable', 'details': str(e)}
        return json.dumps(error_message), 503, [('Content-Type', 'application/json')]

# Generic forwarder for most API calls
@app.route('/api/<service>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def api_forwarder(service, path):
    
    # Determine the service URL
    if service == 'products':
        service_url = PRODUCTS_SERVICE_URL
    elif service == 'admin':
        service_url = ADMIN_SERVICE_URL
    elif service == 'reports':
        service_url = REPORTS_SERVICE_URL
    elif service == 'users':
        service_url = USERS_SERVICE_URL
    else:
        return jsonify({'error': 'Service not found'}), 404

    # Get data from incoming request
    json_payload = request.get_json(silent=True)
    data = request.form if not json_payload else None
    files = request.files or None
    params = request.args
    
    # Inject user/admin ID for services that need it
    if json_payload and 'user_id' not in json_payload and 'admin_id' not in json_payload:
        if 'user_id' in g.current_user:
            json_payload['user_id'] = g.current_user['user_id']
        if 'admin_id' in g.current_user:
            json_payload['admin_id'] = g.current_user['admin_id']
    elif data:
        # For form data, convert to mutable dict to add IDs
        mutable_data = data.to_dict()
        if 'user_id' not in mutable_data and 'admin_id' not in mutable_data:
            if 'user_id' in g.current_user:
                mutable_data['user_id'] = g.current_user['user_id']
            if 'admin_id' in g.current_user:
                mutable_data['admin_id'] = g.current_user['admin_id']
        data = mutable_data


    # Forward request and return response
    content, status_code, headers = forward_request(
        service_url,
        path,
        request.method,
        data=data,
        json_payload=json_payload,
        params=params,
        files=files
    )
    
    return app.response_class(response=content, status=status_code, headers=headers)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
