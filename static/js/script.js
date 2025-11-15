// Form validation for registration
function validateForm() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const username = document.getElementById('username').value;
    const phone = document.getElementById('phone').value;

    // Check if passwords match
    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return false;
    }

    // Check password length
    if (password.length < 6) {
        alert('Password must be at least 6 characters long!');
        return false;
    }

    // Check username length
    if (username.length < 3) {
        alert('Username must be at least 3 characters long!');
        return false;
    }

    // Basic phone validation
    const phoneRegex = /^[0-9+\-\s()]{10,}$/;
    if (!phoneRegex.test(phone)) {
        alert('Please enter a valid phone number!');
        return false;
    }

    return true;
}

// Real-time password matching
document.addEventListener('DOMContentLoaded', function() {
    const password = document.getElementById('password');
    const confirmPassword = document.getElementById('confirm_password');

    if (password && confirmPassword) {
        function validatePassword() {
            if (password.value !== confirmPassword.value) {
                confirmPassword.style.borderColor = 'red';
            } else {
                confirmPassword.style.borderColor = 'green';
            }
        }

        password.addEventListener('keyup', validatePassword);
        confirmPassword.addEventListener('keyup', validatePassword);
    }

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Add loading states to buttons
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.innerHTML = '<i class="bi bi-arrow-repeat spinner"></i> Processing...';
                submitBtn.disabled = true;
            }
        });
    });
});

// Utility functions
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

function formatTime(timeString) {
    if (!timeString) return '';
    return new Date('1970-01-01T' + timeString + 'Z').toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit' 
    });
}

document.addEventListener('DOMContentLoaded', function() {
    // Form validation for registration
    function validateForm() {
        const password = document.getElementById('password');
        const confirmPassword = document.getElementById('confirm_password');
        const username = document.getElementById('username');
        const phone = document.getElementById('phone');

        if (password && confirmPassword) {
            if (password.value !== confirmPassword.value) {
                showToast('Passwords do not match!', 'danger');
                return false;
            }

            if (password.value.length < 6) {
                showToast('Password must be at least 6 characters long!', 'warning');
                return false;
            }
        }

        if (username && username.value.length < 3) {
            showToast('Username must be at least 3 characters long!', 'warning');
            return false;
        }

        if (phone) {
            const phoneRegex = /^[0-9+\-\s()]{10,}$/;
            if (!phoneRegex.test(phone.value)) {
                showToast('Please enter a valid phone number!', 'warning');
                return false;
            }
        }

        return true;
    }

    // Real-time password matching
    const password = document.getElementById('password');
    const confirmPassword = document.getElementById('confirm_password');

    if (password && confirmPassword) {
        function validatePassword() {
            if (password.value !== confirmPassword.value) {
                confirmPassword.style.borderColor = 'red';
            } else {
                confirmPassword.style.borderColor = 'green';
            }
        }

        password.addEventListener('keyup', validatePassword);
        confirmPassword.addEventListener('keyup', validatePassword);
    }

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Add loading states to buttons
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="bi bi-arrow-repeat spinner"></i> Processing...';
                submitBtn.disabled = true;
                
                // Revert after 5 seconds (safety measure)
                setTimeout(() => {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }, 5000);
            }
        });
    });

    // Responsive table handling
    const tables = document.querySelectorAll('table');
    tables.forEach(function(table) {
        if (table.offsetWidth > document.documentElement.clientWidth) {
            table.parentNode.classList.add('table-responsive');
        }
    });

    // Mobile menu enhancement
    const navbarToggler = document.querySelector('.navbar-toggler');
    if (navbarToggler) {
        navbarToggler.addEventListener('click', function() {
            document.body.classList.toggle('menu-open');
        });
    }

    // Card hover effects for touch devices
    if ('ontouchstart' in window) {
        document.querySelectorAll('.card').forEach(card => {
            card.style.cursor = 'pointer';
        });
    }

    // Dynamic content loading for better performance
    function lazyLoadImages() {
        const images = document.querySelectorAll('img[data-src]');
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imageObserver.unobserve(img);
                }
            });
        });

        images.forEach(img => imageObserver.observe(img));
    }

    lazyLoadImages();

    // Toast notification function
    function showToast(message, type = 'info') {
        // Check if toast container exists, if not create one
        let toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            document.body.appendChild(toastContainer);
        }

        const toastId = 'toast-' + Date.now();
        const toastHtml = `
            <div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;

        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement);
        toast.show();

        // Remove toast from DOM after it's hidden
        toastElement.addEventListener('hidden.bs.toast', function() {
            this.remove();
        });
    }

    // Utility functions
    window.formatDate = function(dateString) {
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        return new Date(dateString).toLocaleDateString(undefined, options);
    };

    window.formatTime = function(timeString) {
        if (!timeString) return '';
        return new Date('1970-01-01T' + timeString + 'Z').toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    };

    // Expose validateForm to global scope
    window.validateForm = validateForm;
    window.showToast = showToast;

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    const popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Window resize handling
let resizeTimer;
window.addEventListener('resize', function() {
    document.body.classList.add('resize-animation-stopper');
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
        document.body.classList.remove('resize-animation-stopper');
    }, 400);
});

// Add this to your CSS for resize optimization
const resizeOptimizationCSS = `
.resize-animation-stopper * {
    animation: none !important;
    transition: none !important;
}
`;

// Inject resize optimization CSS
const style = document.createElement('style');
style.textContent = resizeOptimizationCSS;
document.head.appendChild(style);

// Sidebar functionality
document.addEventListener('DOMContentLoaded', function() {
    // Auto-close sidebar on mobile when clicking a link
    const sidebarLinks = document.querySelectorAll('.offcanvas-body .nav-link');
    const sidebar = document.getElementById('sidebar');
    
    sidebarLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (window.innerWidth < 992) {
                const bsOffcanvas = bootstrap.Offcanvas.getInstance(sidebar);
                bsOffcanvas.hide();
            }
        });
    });

    // Add active state based on current page
    function setActiveSidebarLink() {
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.offcanvas-body .nav-link');
        
        navLinks.forEach(link => {
            link.classList.remove('active', 'bg-primary');
            if (link.getAttribute('href') === currentPath) {
                link.classList.add('active', 'bg-primary');
            }
        });
    }

    setActiveSidebarLink();

    // Handle window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth >= 992) {
            // On desktop, ensure sidebar is visible
            const bsOffcanvas = bootstrap.Offcanvas.getInstance(sidebar);
            if (bsOffcanvas) {
                bsOffcanvas.hide();
            }
        }
    });

    // Initialize tooltips for sidebar
    const sidebarTooltips = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const sidebarTooltipList = sidebarTooltips.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});