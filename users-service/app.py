from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
import sys
import os
import requests
import google.generativeai as genai
import json
from dotenv import load_dotenv
import hashlib

load_dotenv()

# Add shared module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.database import get_db
from shared.logger import log_system

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('USERS_SERVICE_SECRET_KEY', 'default-users-secret-key')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default-jwt-secret-key')
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "default_gemini_api_key")
PRODUCTS_SERVICE_URL = os.getenv("PRODUCTS_SERVICE_URL", "http://127.0.0.1:5002")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

def old_hash_password(password):
    """Eski şifreleme yöntemi (geçiş için)"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/register', methods=['POST'])
def register():
    """Kullanıcı kayıt"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'Tüm alanları doldurun!'}), 400
    
    password_hash = generate_password_hash(password)
    
    try:
        with get_db() as conn:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                       (username, email, password_hash))
        log_system('INFO', f'Yeni kullanıcı kaydoldu: {username}', 'users-service', 'register')
        return jsonify({'message': 'Kayıt başarılı!'}), 201
    except Exception as e:
        if 'UNIQUE constraint failed' in str(e):
            return jsonify({'error': 'Bu kullanıcı adı veya email zaten kullanılıyor!'}), 409
        log_system('ERROR', f'Kayıt hatası: {str(e)}', 'users-service', 'register')
        return jsonify({'error': 'Sunucu hatası'}), 500

@app.route('/login', methods=['POST'])
def login():
    """Kullanıcı giriş"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if user:
        # Önce yeni hash ile kontrol et
        if check_password_hash(user['password_hash'], password):
            is_password_valid = True
        # Yeni hash uymazsa, eski hash ile kontrol et (geçiş dönemi için)
        elif user['password_hash'] == old_hash_password(password):
            is_password_valid = True
            # Parolayı yeni hash formatıyla güncelle
            new_password_hash = generate_password_hash(password)
            with get_db() as conn:
                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user['id']))
            log_system('INFO', f'Kullanıcının parolası güncellendi: {username}', 'users-service', 'login')
        else:
            is_password_valid = False

        if is_password_valid:
            token = jwt.encode({
                'user_id': user['id'],
                'username': user['username'],
                'role': 'user',
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, JWT_SECRET_KEY, algorithm='HS256')
            
            log_system('INFO', f'Kullanıcı giriş yaptı: {username}', 'users-service', 'login')
            return jsonify({'message': 'Giriş başarılı!', 'token': token})

    log_system('WARNING', f'Başarısız giriş denemesi: {username}', 'users-service', 'login')
    return jsonify({'error': 'Kullanıcı adı veya şifre hatalı!'}), 401

@app.route('/admin-login', methods=['POST'])
def admin_login():
    """Admin giriş"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    with get_db() as conn:
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()

    if admin:
        # Önce yeni hash ile kontrol et
        if check_password_hash(admin['password_hash'], password):
            is_password_valid = True
        # Yeni hash uymazsa, eski hash ile kontrol et (geçiş dönemi için)
        elif admin['password_hash'] == old_hash_password(password):
            is_password_valid = True
            # Parolayı yeni hash formatıyla güncelle
            new_password_hash = generate_password_hash(password)
            with get_db() as conn:
                conn.execute('UPDATE admins SET password_hash = ? WHERE id = ?', (new_password_hash, admin['id']))
            log_system('INFO', f'Admin parolası güncellendi: {username}', 'users-service', 'admin_login')
        else:
            is_password_valid = False

        if is_password_valid:
            token = jwt.encode({
                'admin_id': admin['id'],
                'admin_username': admin['username'],
                'role': 'admin',
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, JWT_SECRET_KEY, algorithm='HS256')

            log_system('INFO', f'Admin giriş yaptı: {username}', 'users-service', 'admin_login')
            return jsonify({'message': 'Admin girişi başarılı!', 'token': token})

    log_system('WARNING', f'Başarısız admin giriş denemesi: {username}', 'users-service', 'admin_login')
    return jsonify({'error': 'Admin kullanıcı adı veya şifre hatalı!'}), 401

@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    """Kullanıcı profil bilgilerini getirir"""
    with get_db() as conn:
        user = conn.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
    return jsonify(dict(user))

@app.route('/profile/<int:user_id>', methods=['PUT'])
def update_profile(user_id):
    """Kullanıcı profilini günceller"""
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
            if not user:
                return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
            
            # If user wants to change password
            if new_password:
                if not current_password:
                    return jsonify({'error': 'Şifre değişikliği için mevcut şifrenizi girmelisiniz.'}), 400
                
                # Önce yeni hash ile kontrol et
                if not check_password_hash(user['password_hash'], current_password) and \
                   user['password_hash'] != old_hash_password(current_password):
                    return jsonify({'error': 'Mevcut şifreniz yanlış.'}), 403
                
                password_hash = generate_password_hash(new_password)
                conn.execute(
                    'UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?',
                    (username, email, password_hash, user_id)
                )
            else:
                conn.execute(
                    'UPDATE users SET username = ?, email = ? WHERE id = ?',
                    (username, email, user_id)
                )

            log_system('INFO', f'Kullanıcı profilini güncelledi: {username}', 'users-service', 'update_profile')
            return jsonify({'success': True, 'message': 'Profil başarıyla güncellendi.'})
            
    except Exception as e:
        if 'UNIQUE constraint failed' in str(e):
            return jsonify({'error': 'Bu kullanıcı adı veya e-posta başka bir kullanıcı tarafından kullanılıyor.'}), 409
        log_system('ERROR', f'Profil güncellenirken hata: {e}', 'users-service', 'update_profile')
        return jsonify({'error': 'Sunucu hatası'}), 500

@app.route('/llm-process-prompt', methods=['POST'])
def llm_process_prompt():
    """Kullanıcının metin girdisini işleyerek ürün ekleme, silme veya güncelleme yapar."""
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Gemini API anahtarı yapılandırılmamış.'}), 500

    data = request.get_json()
    user_id = data.get('user_id')
    prompt = data.get('prompt')

    if not user_id or not prompt:
        return jsonify({'error': 'Kullanıcı ID ve metin girdisi gerekli'}), 400

    model = genai.GenerativeModel('gemini-1.5-flash')

    # Gemini'ye gönderilecek talimat
    instruction = f"""
    Kullanıcının şu talebini analiz et: "{prompt}"
    Talebin türünü belirle (add, update, delete).
    Ve ilgili ürün bilgilerini bir JSON nesnesi olarak çıkar.
    Ürünlerin adlarının ilk harfleri kesinlikle büyük olmalı.

    JSON formatı şu şekilde olmalı:
    {{
      "action": "add|update|delete",
      "products": [
        {{
          "name": "ürün adı",
          "stock": miktar (sayı),
          "critical_level": kritik stok seviyesi (sayı, belirtilmemişse 5)
        }}
      ]
    }}

    Örnekler:
    - "10 tane defter ekle, kritik stoğu 5 olsun ve 20 tane de kalem ekle kritik stoğu 10 olsun" -> action: "add"
    - "Kalem stoğunu 15 yap" -> action: "update"
    - "Defteri sil" -> action: "delete"
    - "5 adet silgi çıkar" -> action: "update" (stoğu azaltma)

    İstenen Çıktı Örneği (ekleme):
    {{
      "action": "add",
      "products": [
        {{ "name": "Defter", "stock": 10, "critical_level": 5 }},
        {{ "name": "Kalem", "stock": 20, "critical_level": 10 }}
      ]
    }}

    İstenen Çıktı Örneği (güncelleme):
    {{
      "action": "update",
      "products": [
        {{ "name": "Kalem", "stock": 15 }}
      ]
    }}
    
    İstenen Çıktı Örneği (silme):
    {{
      "action": "delete",
      "products": [
        {{ "name": "Defter" }}
      ]
    }}

    Sadece JSON çıktısı ver. Başka hiçbir metin, açıklama veya kod bloğu formatı ekleme.
    """

    try:
        response = model.generate_content(instruction)
        cleaned_response_text = response.text.strip().replace('```json', '').replace('```', '').strip()
        
        data = json.loads(cleaned_response_text)
        action = data.get('action')
        products = data.get('products')

        if not action or not products:
            return jsonify({'error': 'Metinden eylem veya ürün bilgisi çıkarılamadı.'}), 400

        if action == 'add':
            try:
                user_products_response = requests.get(f'{PRODUCTS_SERVICE_URL}/products/user/{user_id}', timeout=120)
                user_products_response.raise_for_status()
                user_products = {p['name'].lower(): p for p in user_products_response.json()}
            except requests.exceptions.RequestException as e:
                log_system('ERROR', f'Kullanıcının ürünleri alınamadı: {e}', 'users-service', 'llm_process_prompt')
                return jsonify({'error': 'Ürünlerinize erişilirken bir hata oluştu.'}), 503

            created = []
            updated = []

            for product_data in products:
                name = product_data.get('name')
                stock = product_data.get('stock', 0)
                critical_level = product_data.get('critical_level', 5)
                name_key = name.lower()

                if name_key in user_products:
                    # ürün zaten varsa, stok artır
                    product_id = user_products[name_key]['id']
                    current_stock = user_products[name_key]['stock']
                    new_stock = current_stock + stock

                    payload = {'user_id': user_id, 'stock': new_stock, 'source': 'llm'}
                    response = requests.put(f'{PRODUCTS_SERVICE_URL}/products/{product_id}', json=payload, timeout=120)
                    if response.ok:
                        updated.append(name)
                else:
                    # ürün yoksa, yeni ekle
                    payload = {'user_id': user_id, 'products': [product_data]}
                    response = requests.post(f'{PRODUCTS_SERVICE_URL}/products/batch-add', json=payload, timeout=120)
                    if response.ok:
                        created.append(name)

            return jsonify({
                'success': True,
                'message': f'{len(created)} ürün eklendi, {len(updated)} ürün güncellendi.',
                'added': created,
                'updated': updated
            }), 200


        # Güncelleme ve Silme işlemleri için kullanıcının mevcut ürünlerini almamız gerekir
        # çünkü ürün ID'lerine ihtiyacımız var.
        try:
            user_products_response = requests.get(f'{PRODUCTS_SERVICE_URL}/products/user/{user_id}', timeout=120)
            user_products_response.raise_for_status()
            user_products = {p['name'].lower(): p for p in user_products_response.json()}
        except requests.exceptions.RequestException as e:
            log_system('ERROR', f'Kullanıcının ürünleri alınamadı: {e}', 'users-service', 'llm_process_prompt')
            return jsonify({'error': 'Ürünlerinize erişilirken bir hata oluştu.'}), 503

        processed_count = 0
        errors = []

        for product_data in products:
            product_name = product_data.get('name')
            if not product_name:
                continue

            product = user_products.get(product_name.lower())
            if not product:
                errors.append(f'{product_name} adında bir ürününüz bulunmuyor.')
                continue

            product_id = product['id']

            if action == 'update':
                # Mevcut stok miktarını al
                existing_stock = product.get('stock')
                new_stock = product_data.get('stock')

                if new_stock is None:
                    errors.append(f'{product_name} için yeni stok miktarı belirtilmemiş.')
                    continue

                # Eğer gelen stok negatifse, bu bir azaltma isteğidir
                if new_stock < 0:
                    updated_stock = existing_stock + new_stock  # çünkü new_stock zaten negatif
                else:
                    updated_stock = new_stock  # doğrudan yeni miktar

                # Negatif stok önlemi
                if updated_stock < 0:
                    errors.append(f'{product_name} stoğu negatif olamaz.')
                    continue

                payload = {'user_id': user_id, 'stock': updated_stock, 'source': 'llm'}
                service_response = requests.put(f'{PRODUCTS_SERVICE_URL}/products/{product_id}', json=payload, timeout=120)

            elif action == 'delete':
                # DELETE request'i body beklemez, user_id'yi payload olarak göndereceğiz.
                service_response = requests.delete(f'{PRODUCTS_SERVICE_URL}/products/{product_id}', json={'user_id': user_id, 'source': 'llm'}, timeout=120)

            if service_response.ok:
                processed_count += 1
            else:
                errors.append(f'{product_name} işlenirken hata: {service_response.text}')
        
        if errors:
            return jsonify({'message': f'{processed_count} ürün işlendi, ancak bazı hatalar var', 'errors': errors}), 207
        
        return jsonify({'success': True, 'message': f'İsteğiniz üzerine {processed_count} ürün başarıyla işlendi.'})


    except json.JSONDecodeError:
        log_system('ERROR', f"Gemini'den geçersiz JSON yanıtı: {cleaned_response_text}", 'users-service', 'llm_process_prompt')
        return jsonify({'error': 'LLM den gelen yanıt işlenemedi. Lütfen tekrar deneyin.'}), 500
    except requests.exceptions.RequestException as e:
        log_system('ERROR', f'Products servisine ulaşılamadı: {e}', 'users-service', 'llm_process_prompt')
        return jsonify({'error': 'Ürün servisine bağlanırken bir hata oluştu.'}), 503
    except Exception as e:
        log_system('ERROR', f'LLM ile işlem hatası: {e}', 'users-service', 'llm_process_prompt')
        return jsonify({'error': f'Bir hata oluştu: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 