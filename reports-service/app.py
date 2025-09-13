from flask import Flask, request, jsonify
import sys
import os

# Add shared module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.database import get_db
from shared.logger import log_system

app = Flask(__name__)

@app.route('/reports/stock-movements/user/<int:user_id>', methods=['GET'])
def api_user_stock_movements(user_id):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    movement_type = request.args.get('movement_type')
    
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
    
    query += ' ORDER BY sm.timestamp DESC'
    
    with get_db() as conn:
        movements = conn.execute(query, params).fetchall()
        stats_query = '''
            SELECT movement_type, COUNT(*) as count, SUM(ABS(quantity_change)) as total_quantity
            FROM stock_movements WHERE user_id = ? '''
        stats_params = [user_id]
        if start_date:
            stats_query += ' AND DATE(timestamp) >= ?'; stats_params.append(start_date)
        if end_date:
            stats_query += ' AND DATE(timestamp) <= ?'; stats_params.append(end_date)
        stats_query += ' GROUP BY movement_type'
        stats = conn.execute(stats_query, stats_params).fetchall()
    
    return jsonify({
        'movements': [dict(m) for m in movements],
        'statistics': [dict(s) for s in stats]
    })

@app.route('/reports/stock-movements/admin', methods=['GET'])
def api_admin_stock_movements():
    start_date, end_date = request.args.get('start_date'), request.args.get('end_date')
    movement_type, username = request.args.get('movement_type'), request.args.get('username')
    
    query = '''
        SELECT sm.*, u.username, p.name as current_product_name
        FROM stock_movements sm JOIN users u ON sm.user_id = u.id
        LEFT JOIN products p ON sm.product_id = p.id WHERE 1=1 '''
    params = []
    
    if start_date: query += ' AND DATE(sm.timestamp) >= ?'; params.append(start_date)
    if end_date: query += ' AND DATE(sm.timestamp) <= ?'; params.append(end_date)
    if movement_type: query += ' AND sm.movement_type = ?'; params.append(movement_type)
    if username: query += ' AND u.username LIKE ?'; params.append(f'%{username}%')
    
    query += ' ORDER BY sm.timestamp DESC'
    
    with get_db() as conn:
        movements = conn.execute(query, params).fetchall()
        stats_query = '''
            SELECT movement_type, COUNT(*) as count, SUM(ABS(quantity_change)) as total_quantity
            FROM stock_movements sm JOIN users u ON sm.user_id = u.id WHERE 1=1 '''
        stats_params = []
        if start_date: stats_query += ' AND DATE(sm.timestamp) >= ?'; stats_params.append(start_date)
        if end_date: stats_query += ' AND DATE(sm.timestamp) <= ?'; stats_params.append(end_date)
        if username: stats_query += ' AND u.username LIKE ?'; stats_params.append(f'%{username}%')
        stats_query += ' GROUP BY movement_type'
        stats = conn.execute(stats_query, stats_params).fetchall()

        user_stats_query = '''
            SELECT u.username, COUNT(*) as total_movements,
                SUM(CASE WHEN sm.movement_type = 'ADD' THEN 1 ELSE 0 END) as additions,
                SUM(CASE WHEN sm.movement_type = 'INCREASE' THEN 1 ELSE 0 END) as increases,
                SUM(CASE WHEN sm.movement_type = 'DECREASE' THEN 1 ELSE 0 END) as decreases,
                SUM(CASE WHEN sm.movement_type = 'DELETE' THEN 1 ELSE 0 END) as deletions
            FROM stock_movements sm JOIN users u ON sm.user_id = u.id WHERE 1=1 '''
        user_stats_params = []
        if start_date: user_stats_query += ' AND DATE(sm.timestamp) >= ?'; user_stats_params.append(start_date)
        if end_date: user_stats_query += ' AND DATE(sm.timestamp) <= ?'; user_stats_params.append(end_date)
        if username: user_stats_query += ' AND u.username LIKE ?'; user_stats_params.append(f'%{username}%')
        user_stats_query += ' GROUP BY u.id, u.username ORDER BY total_movements DESC'
        user_stats = conn.execute(user_stats_query, user_stats_params).fetchall()
    
    return jsonify({
        'movements': [dict(m) for m in movements],
        'statistics': [dict(s) for s in stats],
        'user_statistics': [dict(stat) for stat in user_stats]
    })

@app.route('/reports/summary/user/<int:user_id>', methods=['GET'])
def api_user_reports_summary(user_id):
    with get_db() as conn:
        total_products = conn.execute('SELECT COUNT(*) as count FROM products WHERE user_id = ?', (user_id,)).fetchone()['count']
        critical_products = conn.execute('SELECT COUNT(*) as count FROM products WHERE user_id = ? AND stock < critical_level', (user_id,)).fetchone()['count']
        total_stock = conn.execute('SELECT SUM(stock) as total FROM products WHERE user_id = ?', (user_id,)).fetchone()['total'] or 0
        recent_movements = conn.execute("SELECT COUNT(*) as count FROM stock_movements WHERE user_id = ? AND timestamp > datetime('now', '-30 days')", (user_id,)).fetchone()['count']
        top_products = conn.execute('''
            SELECT product_name, COUNT(*) as movement_count FROM stock_movements WHERE user_id = ?
            GROUP BY product_name ORDER BY movement_count DESC LIMIT 5
        ''', (user_id,)).fetchall()
        monthly_trend = conn.execute('''
            SELECT strftime('%Y-%m', timestamp) as month, COUNT(*) as count
            FROM stock_movements WHERE user_id = ? GROUP BY month ORDER BY month DESC LIMIT 6
        ''', (user_id,)).fetchall()
    
    return jsonify({
        'total_products': total_products, 'critical_products': critical_products,
        'total_stock': total_stock, 'recent_movements': recent_movements,
        'top_products': [dict(p) for p in top_products],
        'monthly_trend': [dict(t) for t in monthly_trend]
    })

@app.route('/reports/summary/admin', methods=['GET'])
def api_admin_reports_summary():
    with get_db() as conn:
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        total_products = conn.execute('SELECT COUNT(*) as count FROM products').fetchone()['count']
        total_movements = conn.execute('SELECT COUNT(*) as count FROM stock_movements').fetchone()['count']
        top_users = conn.execute('''
            SELECT u.username, COUNT(sm.id) as movement_count, COUNT(DISTINCT sm.product_id) as product_count
            FROM users u LEFT JOIN stock_movements sm ON u.id = sm.user_id
            GROUP BY u.id, u.username ORDER BY movement_count DESC LIMIT 5
        ''').fetchall()
        daily_trend = conn.execute('''
            SELECT DATE(timestamp) as date, COUNT(*) as count FROM stock_movements
            WHERE timestamp > datetime('now', '-7 days') GROUP BY date ORDER BY date
        ''').fetchall()
        movement_distribution = conn.execute('''
            SELECT movement_type, COUNT(*) as count FROM stock_movements GROUP BY movement_type
        ''').fetchall()
    
    return jsonify({
        'total_users': total_users, 'total_products': total_products, 'total_movements': total_movements,
        'top_users': [dict(u) for u in top_users], 'daily_trend': [dict(t) for t in daily_trend],
        'movement_distribution': [dict(d) for d in movement_distribution]
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5004) 