from flask import Flask, request, jsonify
import sys
import os
import csv
import io

# Add shared module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.database import get_db
from shared.logger import log_system

app = Flask(__name__)
app.secret_key = 'products-service-secret-key'

def log_activity(user_id, action, description=None, level='INFO'):
    """Kullanıcı aktivitelerini logla"""
    try:
        # In a microservice, we might not have direct access to request, 
        # so IP and User-Agent may need to be passed from the gateway.
        # For now, keeping it simple.
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None

        with get_db() as conn:
            conn.execute('''
                INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent, level)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, action, description, ip_address, user_agent, level))
    except Exception as e:
        print(f"Log hatası: {e}")

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


@app.route('/products/user/<int:user_id>', methods=['GET'])
def api_my_products(user_id):
    """Kullanıcının ürünlerini JSON olarak döndürür"""
    with get_db() as conn:
        products = conn.execute('''
            SELECT id, name, stock, critical_level, 
                   (stock < critical_level) as is_critical
            FROM products 
            WHERE user_id = ? 
            ORDER BY name
        ''', (user_id,)).fetchall()
    
    products_list = [{'id': p['id'], 'name': p['name'], 'stock': p['stock'], 'critical_level': p['critical_level'], 'is_critical': bool(p['is_critical'])} for p in products]
    return jsonify(products_list)

@app.route('/products', methods=['POST'])
def api_add_product():
    """Yeni ürün ekle"""
    data = request.get_json()
    user_id = data.get('user_id')
    name = data.get('name')
    stock = data.get('stock', 0)
    critical_level = data.get('critical_level', 5)
    
    if not name or not user_id:
        return jsonify({'error': 'Ürün adı ve kullanıcı ID si gerekli'}), 400
    
    try:
        with get_db() as conn:
            cursor = conn.execute('''
                INSERT INTO products (user_id, name, stock, critical_level)
                VALUES (?, ?, ?, ?)
            ''', (user_id, name, stock, critical_level))
            
            product_id = cursor.lastrowid
            
        log_stock_movement(user_id, product_id, name, 'ADD', 0, stock, 'Yeni ürün eklendi')
        log_activity(user_id, 'PRODUCT_ADD', f'Yeni ürün eklendi: {name}')
        
        return jsonify({'success': True, 'id': product_id, 'message': 'Ürün başarıyla eklendi'}), 201
    except Exception as e:
        log_system('ERROR', f'Ürün ekleme hatası: {str(e)}', 'products-service', 'api_add_product')
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:product_id>', methods=['PUT'])
def api_update_product(product_id):
    """Ürün güncelle"""
    data = request.get_json()
    user_id = data.get('user_id')
    source = data.get('source')

    if not user_id:
        return jsonify({'error': 'Kullanıcı ID si gerekli'}), 400

    with get_db() as conn:
        product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?',
                              (product_id, user_id)).fetchone()
        
        if not product:
            return jsonify({'error': 'Ürün bulunamadı veya bu kullanıcıya ait değil'}), 404
        
        name = data.get('name', product['name'])
        stock = data.get('stock', product['stock'])
        critical_level = data.get('critical_level', product['critical_level'])
        
        stock_changed = stock != product['stock']
        old_stock = product['stock']
        
        conn.execute('''
            UPDATE products 
            SET name = ?, stock = ?, critical_level = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        ''', (name, stock, critical_level, product_id, user_id))
        
    if stock_changed:
        movement_type = 'INCREASE' if stock > old_stock else 'DECREASE'
        if source == 'llm':
            notes = f'LLM ile stok güncellendi: {old_stock} → {stock}'
        else:
            notes = f'Stok güncellendi: {old_stock} → {stock}'
        log_stock_movement(user_id, product_id, name, movement_type, old_stock, stock, notes)
    
    log_activity(user_id, 'PRODUCT_UPDATE', f'Ürün güncellendi: {name}')
    
    return jsonify({'success': True, 'message': 'Ürün güncellendi'})

@app.route('/products/<int:product_id>', methods=['DELETE'])
def api_delete_product(product_id):
    """Ürün sil"""
    data = request.get_json()
    user_id = data.get('user_id')
    source = data.get('source')

    if not user_id:
        return jsonify({'error': 'Kullanıcı ID si gerekli'}), 400

    with get_db() as conn:
        product = conn.execute('SELECT name, stock FROM products WHERE id = ? AND user_id = ?',
                              (product_id, user_id)).fetchone()
        
        if not product:
            return jsonify({'error': 'Ürün bulunamadı veya bu kullanıcıya ait değil'}), 404
        
        if source == 'llm':
            notes = 'LLM ile ürün silindi'
        else:
            notes = 'Ürün silindi'
        log_stock_movement(user_id, product_id, product['name'], 'DELETE', product['stock'], 0, notes)
        
        result = conn.execute('DELETE FROM products WHERE id = ? AND user_id = ?',
                             (product_id, user_id))
        
        if result.rowcount == 0:
             return jsonify({'error': 'Ürün bulunamadı veya bu kullanıcıya ait değil'}), 404
    
    log_activity(user_id, 'PRODUCT_DELETE', f'Ürün silindi: {product["name"]}')
    
    return jsonify({'success': True, 'message': 'Ürün silindi'})

@app.route('/import-stock', methods=['POST'])
def import_stock():
    """CSV dosyasından stok verilerini içe aktarır."""
    user_id = request.form.get('user_id')
    if 'file' not in request.files or not user_id:
        return jsonify({'error': 'Dosya ve kullanıcı ID si gerekli.'}), 400

    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        return jsonify({'error': 'Geçerli bir CSV dosyası seçilmedi.'}), 400

    try:
        stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
        csv_reader = csv.reader(stream)
        next(csv_reader, None) # başlık
        
        updated_count = 0
        added_count = 0
        
        with get_db() as conn:
            for row in csv_reader:
                if len(row) < 2: continue
                product_name, quantity_change = row[0].strip(), int(row[1].strip())
                
                product = conn.execute('SELECT id, stock, name FROM products WHERE user_id = ? AND LOWER(name) = ?', 
                                       (user_id, product_name.lower())).fetchone()
                
                if product:
                    old_stock = product['stock']
                    new_stock = old_stock + quantity_change
                    conn.execute('UPDATE products SET stock = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (new_stock, product['id']))
                    log_stock_movement(user_id, product['id'], product['name'], 'IMPORT', old_stock, new_stock, f'CSV Import: {quantity_change}')
                    updated_count += 1
                else:
                    cursor = conn.execute('INSERT INTO products (user_id, name, stock) VALUES (?, ?, ?)', (user_id, product_name, quantity_change))
                    product_id = cursor.lastrowid
                    log_stock_movement(user_id, product_id, product_name, 'IMPORT_ADD', 0, quantity_change, f'CSV Import: Yeni ürün eklendi')
                    added_count += 1
        
        message = f"{updated_count} ürün güncellendi, {added_count} yeni ürün eklendi."
        log_activity(user_id, 'STOCK_IMPORT', message)
        return jsonify({'success': True, 'message': message})

    except Exception as e:
        log_system('ERROR', f'CSV import hatası: {e}', 'products-service', 'import_stock')
        return jsonify({'error': f'Dosya işlenirken bir hata oluştu: {e}'}), 500

@app.route('/products/batch-add', methods=['POST'])
def api_batch_add_products():
    """LLM'den gelen ürün listesini toplu olarak ekle"""
    data = request.get_json()
    user_id = data.get('user_id')
    products = data.get('products')

    if not user_id or not products:
        return jsonify({'error': 'Kullanıcı ID si ve ürün listesi gerekli'}), 400

    added_products = []
    try:
        with get_db() as conn:
            for product in products:
                name = product.get('name')
                stock = product.get('stock', 0)
                critical_level = product.get('critical_level', 5)

                if not name:
                    # Ürün adı olmayanları atla
                    continue

                cursor = conn.execute('''
                    INSERT INTO products (user_id, name, stock, critical_level)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, name, stock, critical_level))
                
                product_id = cursor.lastrowid
                added_products.append({'id': product_id, 'name': name})
                
                log_stock_movement(user_id, product_id, name, 'ADD', 0, stock, 'LLM ile toplu ürün eklendi')

        product_names = [p['name'] for p in added_products]
        log_activity(user_id, 'PRODUCT_BATCH_ADD', f'LLM ile toplu ürün eklendi: {", ".join(product_names)}')
        
        return jsonify({
            'success': True, 
            'message': f'{len(added_products)} adet ürün başarıyla eklendi.',
            'added_products': added_products
        }), 201

    except Exception as e:
        log_system('ERROR', f'Toplu ürün ekleme hatası: {str(e)}', 'products-service', 'api_batch_add_products')
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002) 