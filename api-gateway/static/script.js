// Ana sayfa için basit JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Sayfa animasyonları için
    const cards = document.querySelectorAll('.action-card');
    
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.6s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 150);
    });
}); 