// Enhanced Dashboard JavaScript with Modern Features
class DashboardManager {
    constructor() {
        this.products = [];
        this.isLoading = false;
        this.notification = null;
        this.searchTerm = '';
        this.filterStatus = 'all';
        this.sortBy = 'name';
        this.sortOrder = 'asc';
        
        this.init();
    }

    async init() {
        try {
            this.setupEventListeners();
            this.setupThemeToggle();
            await this.loadProducts();
            this.setupAutoRefresh();
        } catch (error) {
            console.error('Dashboard initialization error:', error);
            this.showNotification('Dashboard başlatılamadı', 'error');
        }
    }

    setupEventListeners() {
        // Main action buttons
        document.getElementById('addProductBtn')?.addEventListener('click', () => this.openAddModal());
        document.getElementById('productForm')?.addEventListener('submit', (e) => this.saveProduct(e));
        
        // Modal controls
        window.onclick = (event) => {
        const modal = document.getElementById('productModal');
        if (event.target === modal) {
                this.closeModal();
            }
        };

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeModal();
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.focusSearch();
            }
        });

        // Search and filter
        this.setupSearchAndFilter();
    }

    setupSearchAndFilter() {
        // Create search controls if they don't exist
        this.createSearchControls();

        const searchInput = document.getElementById('searchInput');
        const filterSelect = document.getElementById('filterSelect');
        const sortSelect = document.getElementById('sortSelect');

        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchTerm = e.target.value.toLowerCase();
                    this.renderProducts();
                }, 300);
            });
        }

        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                this.filterStatus = e.target.value;
                this.renderProducts();
            });
        }

        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                const [sortBy, sortOrder] = e.target.value.split('-');
                this.sortBy = sortBy;
                this.sortOrder = sortOrder;
                this.renderProducts();
            });
        }
    }

    createSearchControls() {
        const container = document.querySelector('.dashboard-controls');
        if (!container || document.getElementById('searchInput')) return;

        const searchControls = document.createElement('div');
        searchControls.className = 'search-controls';
        searchControls.innerHTML = `
            <input type="text" id="searchInput" class="search-input" placeholder="Ürün ara... (Ctrl+K)" />
            <select id="filterSelect" class="filter-select">
                <option value="all">Tüm Ürünler</option>
                <option value="normal">Normal Stok</option>
                <option value="critical">Kritik Stok</option>
            </select>
            <select id="sortSelect" class="filter-select">
                <option value="name-asc">İsim A-Z</option>
                <option value="name-desc">İsim Z-A</option>
                <option value="stock-asc">Stok Artan</option>
                <option value="stock-desc">Stok Azalan</option>
                <option value="critical-desc">Kritik Önce</option>
            </select>
        `;

        container.appendChild(searchControls);
    }

    setupThemeToggle() {
        // Create theme toggle button
        if (!document.querySelector('.theme-toggle')) {
            const themeToggle = document.createElement('button');
            themeToggle.className = 'theme-toggle';
            themeToggle.innerHTML = '🌙';
            themeToggle.setAttribute('title', 'Dark/Light Mode');
            
            themeToggle.addEventListener('click', () => this.toggleTheme());
            document.body.appendChild(themeToggle);
        }

        // Load saved theme
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        this.updateThemeIcon(savedTheme);
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        this.updateThemeIcon(newTheme);
        
        this.showNotification(`${newTheme === 'dark' ? 'Karanlık' : 'Aydınlık'} tema aktif`, 'success');
    }

    updateThemeIcon(theme) {
        const toggle = document.querySelector('.theme-toggle');
        if (toggle) {
            toggle.innerHTML = theme === 'dark' ? '☀️' : '🌙';
        }
    }

    focusSearch() {
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.focus();
            searchInput.select();
        }
    }

    setupAutoRefresh() {
        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (!this.isLoading && document.visibilityState === 'visible') {
                this.loadProducts(true); // Silent refresh
            }
        }, 30000);

        // Refresh when tab becomes visible
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && !this.isLoading) {
                this.loadProducts(true);
            }
        });
    }

    async loadProducts(silent = false) {
        if (this.isLoading) return;
        
        this.isLoading = true;
        
        if (!silent) {
            this.showLoading();
        }

        try {
            const response = await fetch('/api/my-products', {
                headers: {
                    'Cache-Control': 'no-cache'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const newProducts = await response.json();
            
            // Check for changes
            if (!silent && this.products.length > 0) {
                this.detectChanges(newProducts);
            }
            
            this.products = newProducts;
            this.updateStats();
            this.renderProducts();
            
            if (!silent) {
                this.hideLoading();
            }
            
        } catch (error) {
            console.error('Products loading error:', error);
            if (!silent) {
                this.showError('Ürünler yüklenirken hata oluştu: ' + error.message);
            }
        } finally {
            this.isLoading = false;
        }
    }

    detectChanges(newProducts) {
        const oldProductsMap = new Map(this.products.map(p => [p.id, p]));
        
        newProducts.forEach(newProduct => {
            const oldProduct = oldProductsMap.get(newProduct.id);
            
            if (!oldProduct) {
                // New product added
                this.showNotification(`Yeni ürün eklendi: ${newProduct.name}`, 'success');
            } else if (oldProduct.stock !== newProduct.stock) {
                // Stock changed
                const change = newProduct.stock - oldProduct.stock;
                const changeText = change > 0 ? `+${change}` : `${change}`;
                this.showNotification(`${newProduct.name} stoğu güncellendi: ${changeText}`, 'info');
            }
        });
    }

    updateStats() {
        const totalProducts = this.products.length;
        const criticalProducts = this.products.filter(p => p.is_critical).length;
        
        this.animateNumber('totalProducts', totalProducts);
        this.animateNumber('criticalProducts', criticalProducts);
    }

    animateNumber(elementId, targetValue) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const currentValue = parseInt(element.textContent) || 0;
        const increment = targetValue > currentValue ? 1 : -1;
        const duration = 500;
        const steps = Math.abs(targetValue - currentValue);
        const stepDuration = duration / steps;

        if (steps === 0) return;

        let current = currentValue;
        const timer = setInterval(() => {
            current += increment;
            element.textContent = current;
            
            if (current === targetValue) {
                clearInterval(timer);
            }
        }, stepDuration);
    }

    filterAndSortProducts() {
        let filtered = [...this.products];

        // Apply search filter
        if (this.searchTerm) {
            filtered = filtered.filter(product => 
                product.name.toLowerCase().includes(this.searchTerm)
            );
        }

        // Apply status filter
        if (this.filterStatus !== 'all') {
            filtered = filtered.filter(product => 
                this.filterStatus === 'critical' ? product.is_critical : !product.is_critical
            );
        }

        // Apply sorting
        filtered.sort((a, b) => {
            let aValue, bValue;
            
            switch (this.sortBy) {
                case 'name':
                    aValue = a.name.toLowerCase();
                    bValue = b.name.toLowerCase();
                    break;
                case 'stock':
                    aValue = a.stock;
                    bValue = b.stock;
                    break;
                case 'critical':
                    aValue = a.is_critical ? 1 : 0;
                    bValue = b.is_critical ? 1 : 0;
                    break;
                default:
                    return 0;
            }

            if (this.sortOrder === 'desc') {
                return aValue < bValue ? 1 : aValue > bValue ? -1 : 0;
            } else {
                return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
            }
        });

        return filtered;
    }

    renderProducts() {
    const container = document.getElementById('productsContainer');
    const emptyState = document.getElementById('emptyState');
    
        if (!container) return;

        const filteredProducts = this.filterAndSortProducts();
    
        if (filteredProducts.length === 0) {
        container.style.display = 'none';
            if (emptyState) {
        emptyState.style.display = 'block';
                emptyState.innerHTML = this.searchTerm || this.filterStatus !== 'all' 
                    ? this.getNoResultsHTML() 
                    : this.getEmptyStateHTML();
            }
        return;
    }
    
        if (emptyState) emptyState.style.display = 'none';
    container.style.display = 'grid';
        
        // Use DocumentFragment for better performance
        const fragment = document.createDocumentFragment();
        
        filteredProducts.forEach((product, index) => {
            const productCard = this.createProductCard(product, index);
            fragment.appendChild(productCard);
        });
        
    container.innerHTML = '';
        container.appendChild(fragment);
    }

    getEmptyStateHTML() {
        return `
            <div class="empty-icon">📦</div>
            <h3>Henüz ürün eklenmemiş</h3>
            <p>İlk ürününüzü ekleyerek başlayın!</p>
            <button onclick="dashboard.openAddModal()" class="add-btn">İlk Ürünü Ekle</button>
        `;
    }

    getNoResultsHTML() {
        return `
            <div class="empty-icon">🔍</div>
            <h3>Sonuç bulunamadı</h3>
            <p>Arama kriterlerinizi değiştirerek tekrar deneyin.</p>
            <button onclick="dashboard.clearFilters()" class="btn">Filtreleri Temizle</button>
        `;
    }

    clearFilters() {
        this.searchTerm = '';
        this.filterStatus = 'all';
        this.sortBy = 'name';
        this.sortOrder = 'asc';
        
        const searchInput = document.getElementById('searchInput');
        const filterSelect = document.getElementById('filterSelect');
        const sortSelect = document.getElementById('sortSelect');
        
        if (searchInput) searchInput.value = '';
        if (filterSelect) filterSelect.value = 'all';
        if (sortSelect) sortSelect.value = 'name-asc';
        
        this.renderProducts();
    }

    createProductCard(product, index) {
    const card = document.createElement('div');
    card.className = `product-card ${product.is_critical ? 'critical' : ''}`;
        card.style.animationDelay = `${index * 0.1}s`;
    
    card.innerHTML = `
        <div class="product-header">
                <h4>${product.is_critical ? '🔴 ' : ''}${this.escapeHtml(product.name)}</h4>
            <div class="product-actions">
                    <button onclick="dashboard.editProduct(${product.id})" class="edit-btn" title="Düzenle">✏️</button>
                    <button onclick="dashboard.deleteProduct(${product.id})" class="delete-btn" title="Sil">🗑️</button>
                </div>
        </div>
        
        <div class="product-details">
            <div class="detail-item">
                <span class="detail-label">Stok:</span>
                <span class="detail-value">${product.stock}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Kritik Seviye:</span>
                <span class="detail-value">${product.critical_level}</span>
            </div>
                <div class="detail-item">
                    <span class="detail-label">Son Güncelleme:</span>
                    <span class="detail-value">${this.formatDate(product.updated_at)}</span>
                </div>
        </div>
        
        <div class="stock-actions">
                <button onclick="dashboard.updateStock(${product.id}, -1)" class="stock-btn minus" title="Stok Azalt">-</button>
            <span class="stock-value">${product.stock}</span>
                <button onclick="dashboard.updateStock(${product.id}, 1)" class="stock-btn plus" title="Stok Artır">+</button>
        </div>
        
        ${product.is_critical ? '<div class="critical-badge">KRİTİK STOK!</div>' : ''}
    `;
    
    return card;
}

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatDate(dateString) {
        if (!dateString) return 'Bilinmiyor';
        
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Şimdi';
        if (diffMins < 60) return `${diffMins} dk önce`;
        if (diffHours < 24) return `${diffHours} saat önce`;
        if (diffDays < 7) return `${diffDays} gün önce`;
        
        return date.toLocaleDateString('tr-TR');
    }

    openAddModal() {
    document.getElementById('modalTitle').textContent = 'Yeni Ürün Ekle';
    document.getElementById('productId').value = '';
    document.getElementById('productForm').reset();
        
        const modal = document.getElementById('productModal');
        modal.style.display = 'block';
        
        // Focus first input
        setTimeout(() => {
            document.getElementById('productName')?.focus();
        }, 100);
    }

    editProduct(productId) {
        const product = this.products.find(p => p.id === productId);
        if (!product) {
            this.showNotification('Ürün bulunamadı', 'error');
            return;
        }
    
    document.getElementById('modalTitle').textContent = 'Ürün Düzenle';
    document.getElementById('productId').value = product.id;
    document.getElementById('productName').value = product.name;
    document.getElementById('productStock').value = product.stock;
    document.getElementById('productCritical').value = product.critical_level;
        
    document.getElementById('productModal').style.display = 'block';
        
        // Focus first input
        setTimeout(() => {
            document.getElementById('productName')?.focus();
        }, 100);
    }

    closeModal() {
        const modal = document.getElementById('productModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async saveProduct(event) {
    event.preventDefault();
        
        const submitBtn = event.target.querySelector('.save-btn');
        const originalText = submitBtn.textContent;
        
        try {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<div class="spinner" style="width: 16px; height: 16px; margin: 0 auto;"></div>';
    
    const productId = document.getElementById('productId').value;
            const name = document.getElementById('productName').value.trim();
    const stock = parseInt(document.getElementById('productStock').value);
    const critical_level = parseInt(document.getElementById('productCritical').value);
            
            // Validation
            if (!name) {
                throw new Error('Ürün adı boş olamaz');
            }
            if (stock < 0) {
                throw new Error('Stok miktarı negatif olamaz');
            }
            if (critical_level < 1) {
                throw new Error('Kritik seviye en az 1 olmalı');
            }
    
    const productData = { name, stock, critical_level };
    
        let response;
        if (productId) {
            response = await fetch(`/api/update-product/${productId}`, {
                method: 'PUT',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-cache'
                    },
                body: JSON.stringify(productData)
            });
        } else {
            response = await fetch('/api/add-product', {
                method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-cache'
                    },
                body: JSON.stringify(productData)
            });
        }
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        
        const result = await response.json();
        
        if (result.success) {
                this.closeModal();
                await this.loadProducts();
                this.showNotification(result.message || 'İşlem başarılı', 'success');
        } else {
                throw new Error(result.error || 'İşlem başarısız');
        }
        
    } catch (error) {
            console.error('Save product error:', error);
            this.showNotification('Kayıt hatası: ' + error.message, 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }

    async updateStock(productId, change) {
        const product = this.products.find(p => p.id === productId);
        if (!product) {
            this.showNotification('Ürün bulunamadı', 'error');
            return;
        }
    
    const newStock = Math.max(0, product.stock + change);
        
        // Optimistic update
        const oldStock = product.stock;
        product.stock = newStock;
        this.renderProducts();
        this.updateStats();
    
    try {
        const response = await fetch(`/api/update-product/${productId}`, {
            method: 'PUT',
                headers: { 
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache'
                },
            body: JSON.stringify({ stock: newStock })
        });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        
        const result = await response.json();
            if (!result.success) {
                throw new Error(result.error || 'Güncelleme başarısız');
        }
        
    } catch (error) {
            console.error('Stock update error:', error);
            // Revert optimistic update
            product.stock = oldStock;
            this.renderProducts();
            this.updateStats();
            this.showNotification('Stok güncellenemedi: ' + error.message, 'error');
        }
    }

    async deleteProduct(productId) {
        const product = this.products.find(p => p.id === productId);
        if (!product) {
            this.showNotification('Ürün bulunamadı', 'error');
            return;
        }

        const confirmed = await this.showConfirmDialog(
            'Ürünü Sil',
            `"${product.name}" ürününü silmek istediğinizden emin misiniz? Bu işlem geri alınamaz.`
        );
        
        if (!confirmed) return;
    
    try {
        const response = await fetch(`/api/delete-product/${productId}`, {
                method: 'DELETE',
                headers: {
                    'Cache-Control': 'no-cache'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            if (result.success) {
                await this.loadProducts();
                this.showNotification(result.message || 'Ürün silindi', 'success');
            } else {
                throw new Error(result.error || 'Silme işlemi başarısız');
            }
            
        } catch (error) {
            console.error('Delete product error:', error);
            this.showNotification('Silme hatası: ' + error.message, 'error');
        }
    }

    showLoading() {
        const loading = document.getElementById('loading');
        const container = document.getElementById('productsContainer');
        const emptyState = document.getElementById('emptyState');
        
        if (loading) loading.style.display = 'block';
        if (container) container.style.display = 'none';
        if (emptyState) emptyState.style.display = 'none';
    }

    hideLoading() {
        const loading = document.getElementById('loading');
        if (loading) loading.style.display = 'none';
    }

    showError(message) {
        this.hideLoading();
        const error = document.getElementById('error');
        const errorMessage = document.getElementById('errorMessage');
        const container = document.getElementById('productsContainer');
        const emptyState = document.getElementById('emptyState');
        
        if (error && errorMessage) {
            errorMessage.textContent = message;
            error.style.display = 'block';
        }
        if (container) container.style.display = 'none';
        if (emptyState) emptyState.style.display = 'none';
        
        this.showNotification(message, 'error');
    }

    showNotification(message, type = 'info', duration = 5000) {
        // Remove existing notification
        if (this.notification) {
            this.notification.remove();
        }
        
    const notification = document.createElement('div');
        notification.className = `notification ${type}`;
    notification.textContent = message;
        
    document.body.appendChild(notification);
        this.notification = notification;
    
        // Auto remove
    setTimeout(() => {
            if (this.notification === notification) {
                notification.remove();
                this.notification = null;
            }
        }, duration);
        
        // Click to dismiss
        notification.addEventListener('click', () => {
        notification.remove();
            if (this.notification === notification) {
                this.notification = null;
            }
        });
    }

    async showConfirmDialog(title, message) {
        return new Promise((resolve) => {
            // Create modal dialog
            const dialog = document.createElement('div');
            dialog.className = 'modal';
            dialog.style.display = 'block';
            
            dialog.innerHTML = `
                <div class="modal-content" style="max-width: 400px;">
                    <div class="modal-header">
                        <h3>${title}</h3>
                    </div>
                    <div class="modal-form">
                        <p style="margin-bottom: 2rem; line-height: 1.6;">${message}</p>
                        <div class="modal-actions">
                            <button type="button" class="cancel-btn" onclick="this.closest('.modal').remove(); window.confirmCallback(false);">İptal</button>
                            <button type="button" class="save-btn" style="background: var(--danger-color);" onclick="this.closest('.modal').remove(); window.confirmCallback(true);">Sil</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(dialog);
            
            window.confirmCallback = (result) => {
                delete window.confirmCallback;
                resolve(result);
            };
        });
    }
}

// Initialize dashboard when DOM is ready
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new DashboardManager();
});

// Expose functions globally for onclick handlers
window.dashboard = {
    openAddModal: () => dashboard?.openAddModal(),
    editProduct: (id) => dashboard?.editProduct(id),
    deleteProduct: (id) => dashboard?.deleteProduct(id),
    updateStock: (id, change) => dashboard?.updateStock(id, change),
    clearFilters: () => dashboard?.clearFilters()
}; 