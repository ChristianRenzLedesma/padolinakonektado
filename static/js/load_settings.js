// Load saved settings
function loadSettings() {
    // Fetch backend settings via AJAX
    fetch('/system_settings', {
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.settings && Object.keys(data.settings).length > 0) {
                const settings = data.settings;
                
                // System settings
                if (settings.system_name && document.getElementById('systemName')) {
                    document.getElementById('systemName').value = settings.system_name;
                }
                if (settings.system_description && document.getElementById('systemDescription')) {
                    document.getElementById('systemDescription').value = settings.system_description;
                }
                if (settings.admin_email && document.getElementById('adminEmail')) {
                    document.getElementById('adminEmail').value = settings.admin_email;
                }
                if (settings.items_per_page && document.getElementById('itemsPerPage')) {
                    document.getElementById('itemsPerPage').value = settings.items_per_page;
                }
                if (settings.user_registration && document.getElementById('userRegistration')) {
                    document.getElementById('userRegistration').checked = settings.user_registration === 'True';
                }
                if (settings.email_verification && document.getElementById('emailVerification')) {
                    document.getElementById('emailVerification').checked = settings.email_verification === 'True';
                }
                if (settings.admin_approval && document.getElementById('adminApproval')) {
                    document.getElementById('adminApproval').checked = settings.admin_approval === 'True';
                }
                if (settings.auto_save && document.getElementById('autoSave')) {
                    document.getElementById('autoSave').checked = settings.auto_save === 'True';
                }
                
                // Security settings
                if (settings.security_min_password_length && document.getElementById('minPasswordLength')) {
                    document.getElementById('minPasswordLength').value = settings.security_min_password_length;
                }
                if (settings.security_password_expiry && document.getElementById('passwordExpiry')) {
                    document.getElementById('passwordExpiry').value = settings.security_password_expiry;
                }
                if (settings.security_session_timeout && document.getElementById('sessionTimeout')) {
                    document.getElementById('sessionTimeout').value = settings.security_session_timeout;
                }
                if (settings.security_max_login_attempts && document.getElementById('maxLoginAttempts')) {
                    document.getElementById('maxLoginAttempts').value = settings.security_max_login_attempts;
                }
                if (settings.security_require_special_chars && document.getElementById('requireSpecialChars')) {
                    document.getElementById('requireSpecialChars').checked = settings.security_require_special_chars === 'True';
                }
                if (settings.security_require_numbers && document.getElementById('requireNumbers')) {
                    document.getElementById('requireNumbers').checked = settings.security_require_numbers === 'True';
                }
                if (settings.security_remember_me && document.getElementById('rememberMe')) {
                    document.getElementById('rememberMe').checked = settings.security_remember_me === 'True';
                }
                if (settings.security_two_factor_auth && document.getElementById('twoFactorAuth')) {
                    document.getElementById('twoFactorAuth').checked = settings.security_two_factor_auth === 'True';
                }
                if (settings.security_login_attempts && document.getElementById('loginAttempts')) {
                    document.getElementById('loginAttempts').checked = settings.security_login_attempts === 'True';
                }
                
                // Email settings
                if (settings.email_smtp_server && document.getElementById('smtpServer')) {
                    document.getElementById('smtpServer').value = settings.email_smtp_server;
                }
                if (settings.email_smtp_port && document.getElementById('smtpPort')) {
                    document.getElementById('smtpPort').value = settings.email_smtp_port;
                }
                if (settings.email_smtp_username && document.getElementById('smtpUsername')) {
                    document.getElementById('smtpUsername').value = settings.email_smtp_username;
                }
                if (settings.email_smtp_password && document.getElementById('smtpPassword')) {
                    document.getElementById('smtpPassword').value = settings.email_smtp_password;
                }
                if (settings.email_from_email && document.getElementById('fromEmail')) {
                    document.getElementById('fromEmail').value = settings.email_from_email;
                }
                if (settings.email_from_name && document.getElementById('fromName')) {
                    document.getElementById('fromName').value = settings.email_from_name;
                }
                if (settings.email_smtp_tls && document.getElementById('smtpTLS')) {
                    document.getElementById('smtpTLS').checked = settings.email_smtp_tls === 'True';
                }
                
                // Backup settings
                if (settings.auto_backup && document.getElementById('autoBackup')) {
                    document.getElementById('autoBackup').checked = settings.auto_backup === 'True';
                }
                if (settings.backup_frequency && document.getElementById('backupFrequency')) {
                    document.getElementById('backupFrequency').value = settings.backup_frequency;
                }
                if (settings.backup_retention && document.getElementById('backupRetention')) {
                    document.getElementById('backupRetention').value = settings.backup_retention;
                }
            }
        })
        .catch(error => {
            console.error('Error loading settings:', error);
        });
    
    // Appearance settings
    const darkMode = localStorage.getItem('darkMode') === 'true';
    const themeVariant = localStorage.getItem('themeVariant') || 'light';
    const fontSize = localStorage.getItem('fontSize') || 'medium';
    
    document.getElementById('darkModeToggle').checked = darkMode;
    document.querySelector(`input[name="themeVariant"][value="${themeVariant}"]`).checked = true;
    document.getElementById('fontSize').value = fontSize;
    
    // Apply appearance settings
    if (darkMode || themeVariant === 'dark') {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    
    const sizes = ['font-small', 'font-medium', 'font-large', 'font-extra-large'];
    sizes.forEach(size => document.body.classList.remove(size));
    document.body.classList.add(`font-${fontSize}`);
}
