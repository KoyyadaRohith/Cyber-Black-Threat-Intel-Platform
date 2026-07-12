document.addEventListener('DOMContentLoaded', () => {
    // Mobile menu toggle logic
    const body = document.body;
    const sidebar = document.querySelector('.app-sidebar');
    
    // Add mobile toggle button dynamically if inside an authenticated page
    if (sidebar && !document.querySelector('.mobile-menu-toggle')) {
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'mobile-menu-toggle';
        toggleBtn.style.display = 'none'; // Controlled by responsive.css media query
        toggleBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="4" x2="20" y1="12" y2="12"></line>
                <line x1="4" x2="20" y1="6" y2="6"></line>
                <line x1="4" x2="20" y1="18" y2="18"></line>
            </svg>
        `;
        document.body.appendChild(toggleBtn);
        
        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            sidebar.classList.toggle('active');
        });
        
        // Close sidebar when clicking outside of it
        document.addEventListener('click', (e) => {
            if (sidebar.classList.contains('active') && !sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
                sidebar.classList.remove('active');
            }
        });
    }

    // Copy to clipboard helper
    const copyBtns = document.querySelectorAll('.copy-trigger');
    copyBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-copy-target');
            const targetEl = document.getElementById(targetId);
            const textToCopy = targetEl ? targetEl.textContent || targetEl.value : btn.getAttribute('data-copy-text');
            
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy.trim()).then(() => {
                    const originalHTML = btn.innerHTML;
                    btn.innerHTML = '<span style="color: var(--color-safe)">Copied!</span>';
                    setTimeout(() => {
                        btn.innerHTML = originalHTML;
                    }, 1500);
                });
            }
        });
    });

    // Auto fade out alerts
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.5s ease';
            setTimeout(() => {
                alert.remove();
            }, 500);
        }, 4000);
    });

    // Theme Switcher Toggle Handler
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    const updateThemeIcon = (theme) => {
        const icon = themeToggleBtn.querySelector('i');
        if (icon) {
            if (theme === 'light') {
                icon.setAttribute('data-lucide', 'sun');
                icon.style.color = '#eab308';
            } else {
                icon.setAttribute('data-lucide', 'moon');
                icon.style.color = 'var(--primary)';
            }
            if (window.lucide) lucide.createIcons();
        }
    };

    if (themeToggleBtn) {
        const activeTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        updateThemeIcon(activeTheme);

        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
        });
    }

    // Numeric counter animation helper
    const counterElements = document.querySelectorAll('.animate-counter');
    counterElements.forEach(el => {
        const endVal = parseInt(el.getAttribute('data-target-val'), 10) || 0;
        let startVal = 0;
        const duration = 1500;
        const steps = 40;
        const increment = endVal / steps;
        const stepTime = duration / steps;
        
        let current = 0;
        const timer = setInterval(() => {
            current += increment;
            if (current >= endVal) {
                el.textContent = endVal;
                clearInterval(timer);
            } else {
                el.textContent = Math.floor(current);
            }
        }, stepTime);
    });

    // Particles connection background canvas
    const canvas = document.getElementById('particlesCanvas');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        let width = canvas.width = canvas.offsetWidth;
        let height = canvas.height = canvas.offsetHeight;
        
        window.addEventListener('resize', () => {
            width = canvas.width = canvas.offsetWidth;
            height = canvas.height = canvas.offsetHeight;
        });
        
        const particles = [];
        const particleCount = 70;
        
        for (let i = 0; i < particleCount; i++) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.5,
                vy: (Math.random() - 0.5) * 0.5,
                r: Math.random() * 2 + 1
            });
        }
        
        function animate() {
            ctx.clearRect(0, 0, width, height);
            
            // Draw connections
            ctx.lineWidth = 0.5;
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            ctx.strokeStyle = currentTheme === 'light' ? 'rgba(2, 132, 199, 0.08)' : 'rgba(0, 240, 255, 0.05)';
            
            for (let i = 0; i < particleCount; i++) {
                for (let j = i + 1; j < particleCount; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    
                    if (dist < 120) {
                        ctx.beginPath();
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.stroke();
                    }
                }
            }
            
            // Draw particles
            ctx.fillStyle = currentTheme === 'light' ? 'rgba(2, 132, 199, 0.3)' : 'rgba(0, 240, 255, 0.4)';
            for (let i = 0; i < particleCount; i++) {
                const p = particles[i];
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fill();
                
                p.x += p.vx;
                p.y += p.vy;
                
                if (p.x < 0 || p.x > width) p.vx *= -1;
                if (p.y < 0 || p.y > height) p.vy *= -1;
            }
            
            requestAnimationFrame(animate);
        }
        
        animate();
    }

    // Dynamic risk bar initialization to avoid Jinja templates in inline styles
    const riskBars = document.querySelectorAll('.dynamic-risk-bar');
    riskBars.forEach(bar => {
        const score = bar.getAttribute('data-risk-score');
        if (score) {
            bar.style.width = score + '%';
        }
    });
});
