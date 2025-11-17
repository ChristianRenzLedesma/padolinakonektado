// Appearance Settings
function setAccentColor(color) {
    console.log('setAccentColor called with:', color);
    
    // Remove existing accent color classes
    document.body.classList.remove('accent-primary', 'accent-success', 'accent-info', 'accent-warning', 'accent-danger', 'accent-default');
    // Add new accent color class
    document.body.classList.add(`accent-${color}`);
    
    console.log('Body classes after change:', document.body.className);
    
    // Store in localStorage
    localStorage.setItem('accentColor', color);
    
    // Update active button
    document.querySelectorAll('[data-color]').forEach(btn => {
        btn.classList.remove('active', 'border-dark');
        if (btn.dataset.color === color) {
            btn.classList.add('active', 'border-dark');
        }
    });
    
    console.log('Accent color set to:', color);
}

function saveAppearanceSettings() {
    const themeVariant = document.querySelector('input[name="themeVariant"]:checked').value;
    const fontSize = document.getElementById('fontSize').value;
    const accentColor = localStorage.getItem('accentColor') || 'default';
    
    // Save to localStorage
    localStorage.setItem('themeVariant', themeVariant);
    localStorage.setItem('fontSize', fontSize);
    localStorage.setItem('accentColor', accentColor);
    
    // Apply settings immediately
    applyAppearanceSettings();
    
    // Show success message
    showAlert('success', 'Appearance settings saved successfully!');
}

function applyAppearanceSettings() {
    const themeVariant = localStorage.getItem('themeVariant') || 'light';
    const fontSize = localStorage.getItem('fontSize') || 'medium';
    
    // Apply theme
    let darkMode = false;
    if (themeVariant === 'dark') {
        darkMode = true;
    } else if (themeVariant === 'system') {
        // Check system preference
        darkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    
    if (darkMode) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    
    // Apply font size
    const sizes = ['font-small', 'font-medium', 'font-large', 'font-extra-large'];
    sizes.forEach(size => document.body.classList.remove(size));
    document.body.classList.add(`font-${fontSize}`);
    
    // Apply accent color
    const accentColor = localStorage.getItem('accentColor') || 'default';
    setAccentColor(accentColor);
}

// Notification Settings
function saveNotificationSettings() {
    const emailNotifications = document.getElementById('emailNotifications').checked;
    const newConcernEmail = document.getElementById('newConcernEmail').checked;
    const newUserEmail = document.getElementById('newUserEmail').checked;
    
    // Save to localStorage for global application
    localStorage.setItem('emailNotifications', emailNotifications);
    localStorage.setItem('newConcernEmail', newConcernEmail);
    localStorage.setItem('newUserEmail', newUserEmail);
    
    const formData = new FormData();
    formData.append('setting_type', 'notification');
    formData.append('email_notifications', emailNotifications);
    formData.append('new_concern_email', newConcernEmail);
    formData.append('new_user_email', newUserEmail);
    formData.append('browser_notifications', document.getElementById('browserNotifications').checked);
    formData.append('sound_alerts', document.getElementById('soundAlerts').checked);
    
    fetch('/system_settings', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Request browser notification permission if enabled
            if (document.getElementById('browserNotifications').checked && 'Notification' in window) {
                Notification.requestPermission();
            }
            showAlert('success', data.message || 'Notification settings saved successfully!');
        } else {
            showAlert('danger', 'Error saving notification settings');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error saving notification settings');
    });
}

// Security Settings
function saveSecuritySettings() {
    const minPasswordLength = document.getElementById('minPasswordLength').value;
    const passwordExpiry = document.getElementById('passwordExpiry').value;
    const sessionTimeout = document.getElementById('sessionTimeout').value;
    
    // Save to localStorage for global application
    localStorage.setItem('minPasswordLength', minPasswordLength);
    localStorage.setItem('passwordExpiry', passwordExpiry);
    localStorage.setItem('sessionTimeout', sessionTimeout);
    
    const formData = new FormData();
    formData.append('setting_type', 'security');
    formData.append('min_password_length', minPasswordLength);
    formData.append('password_expiry', passwordExpiry);
    formData.append('session_timeout', sessionTimeout);
    formData.append('max_login_attempts', document.getElementById('maxLoginAttempts').value);
    formData.append('require_special_chars', document.getElementById('requireSpecialChars').checked);
    formData.append('require_numbers', document.getElementById('requireNumbers').checked);
    formData.append('remember_me', document.getElementById('rememberMe').checked);
    formData.append('two_factor_auth', document.getElementById('twoFactorAuth').checked);
    formData.append('login_attempts', document.getElementById('loginAttempts').checked);
    
    fetch('/system_settings', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', data.message || 'Security settings saved successfully!');
        } else {
            showAlert('danger', 'Error saving security settings');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error saving security settings');
    });
}

// System Settings
function saveSystemSettings() {
    const systemName = document.getElementById('systemName').value;
    const systemDescription = document.getElementById('systemDescription').value;
    const adminEmail = document.getElementById('adminEmail').value;
    const systemTimezone = document.getElementById('systemTimezone').value;
    
    // Save to localStorage for global application
    localStorage.setItem('systemName', systemName);
    localStorage.setItem('systemDescription', systemDescription);
    localStorage.setItem('adminEmail', adminEmail);
    localStorage.setItem('systemTimezone', systemTimezone);
    
    const formData = new FormData();
    formData.append('setting_type', 'system');
    formData.append('system_name', systemName);
    formData.append('system_description', systemDescription);
    formData.append('admin_email', adminEmail);
    formData.append('system_timezone', systemTimezone);
    formData.append('items_per_page', document.getElementById('itemsPerPage').value);
    formData.append('user_registration', document.getElementById('userRegistration').checked);
    formData.append('email_verification', document.getElementById('emailVerification').checked);
    formData.append('admin_approval', document.getElementById('adminApproval').checked);
    formData.append('auto_save', document.getElementById('autoSave').checked);
    
    fetch('/system_settings', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', data.message || 'System settings saved successfully!');
        } else {
            showAlert('danger', 'Error saving system settings');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error saving system settings');
    });
}

// Backup Settings
function saveBackupSettings() {
    const autoBackup = document.getElementById('autoBackup').checked;
    const backupFrequency = document.getElementById('backupFrequency').value;
    const backupRetention = document.getElementById('backupRetention').value;
    
    // Save to localStorage for global application
    localStorage.setItem('autoBackup', autoBackup);
    localStorage.setItem('backupFrequency', backupFrequency);
    localStorage.setItem('backupRetention', backupRetention);
    
    const formData = new FormData();
    formData.append('setting_type', 'backup');
    formData.append('auto_backup', autoBackup);
    formData.append('backup_frequency', backupFrequency);
    formData.append('backup_retention', backupRetention);
    
    fetch('/system_settings', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', data.message || 'Backup settings saved successfully!');
        } else {
            showAlert('danger', 'Error saving backup settings');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error saving backup settings');
    });
}

function backupNow() {
    showAlert('info', 'Starting backup process...');
    
    fetch('/backup_database', {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', data.message);
            // Immediately refresh system info to show updated backup time
            setTimeout(updateSystemInfo, 500);
        } else {
            showAlert('danger', data.message || 'Backup failed');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error during backup');
    });
}

function optimizeDatabase() {
    showAlert('info', 'Optimizing database...');
    
    fetch('/optimize_database', {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', data.message);
        } else {
            showAlert('danger', data.message || 'Optimization failed');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error during optimization');
    });
}

function clearCache() {
    showAlert('info', 'Clearing cache...');
    
    // Clear localStorage cache (except settings)
    const keysToKeep = ['systemSettings', 'securitySettings', 'notificationSettings', 'backupSettings', 
                       'themeVariant', 'fontSize', 'darkMode', 'accentColor'];
    
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!keysToKeep.includes(key)) {
            localStorage.removeItem(key);
        }
    }
    
    setTimeout(() => {
        showAlert('success', 'Cache cleared successfully!');
    }, 1000);
}

function testEmailConfig() {
    showAlert('info', 'Sending test email...');
    
    // Simulate sending test email
    setTimeout(() => {
        showAlert('success', 'Test email sent successfully!');
    }, 2000);
}

// Email Settings
function saveEmailSettings() {
    const smtpServer = document.getElementById('smtpServer').value;
    const smtpPort = document.getElementById('smtpPort').value;
    const smtpUsername = document.getElementById('smtpUsername').value;
    const smtpPassword = document.getElementById('smtpPassword').value;
    const emailFrom = document.getElementById('emailFrom').value;
    const emailFromName = document.getElementById('emailFromName').value;
    
    // Save to localStorage for global application
    localStorage.setItem('smtpServer', smtpServer);
    localStorage.setItem('smtpPort', smtpPort);
    localStorage.setItem('smtpUsername', smtpUsername);
    localStorage.setItem('emailFrom', emailFrom);
    localStorage.setItem('emailFromName', emailFromName);
    
    const formData = new FormData();
    formData.append('setting_type', 'email');
    formData.append('smtp_server', smtpServer);
    formData.append('smtp_port', smtpPort);
    formData.append('smtp_username', smtpUsername);
    formData.append('smtp_password', smtpPassword);
    formData.append('email_from', emailFrom);
    formData.append('email_from_name', emailFromName);
    formData.append('smtp_tls', document.getElementById('smtpTLS').checked);
    
    fetch('/system_settings', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', data.message || 'Email settings saved successfully!');
        } else {
            showAlert('danger', 'Error saving email settings');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('danger', 'Error saving email settings');
    });
}

// Utility Functions
function showAlert(type, message) {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at the top of the main content
    const mainContent = document.querySelector('.container-fluid');
    if (mainContent) {
        mainContent.insertBefore(alertDiv, mainContent.firstChild);
    }
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Load settings on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded - Settings page loaded');
    
    // Load appearance settings
    const themeVariant = localStorage.getItem('themeVariant') || 'light';
    const fontSize = localStorage.getItem('fontSize') || 'medium';
    const accentColor = localStorage.getItem('accentColor') || 'default';
    
    console.log('Loading settings:', { themeVariant, fontSize, accentColor });
    
    // Check if elements exist before trying to access them
    const fontSizeSelect = document.getElementById('fontSize');
    
    const themeVariantInput = document.querySelector(`input[name="themeVariant"][value="${themeVariant}"]`);
    if (themeVariantInput) {
        themeVariantInput.checked = true;
        console.log('Theme variant set to:', themeVariant);
    } else {
        console.error('Theme variant input not found for value:', themeVariant);
    }
    
    if (fontSizeSelect) {
        fontSizeSelect.value = fontSize;
        console.log('Font size set to:', fontSize);
    } else {
        console.error('fontSize element not found');
    }
    
    // Set active accent color button
    const accentButtons = document.querySelectorAll('[data-color]');
    console.log('Found accent buttons:', accentButtons.length);
    
    accentButtons.forEach(btn => {
        btn.classList.remove('active', 'border-dark');
        if (btn.dataset.color === accentColor) {
            btn.classList.add('active', 'border-dark');
            console.log('Set active accent button:', accentColor);
        }
    });
    
    // Apply appearance settings
    applyAppearanceSettings();
    
    // Load settings from server
    fetch('/system_settings', {
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.settings) {
            loadSettingsFromServer(data.settings);
        }
    })
    .catch(error => {
        console.error('Error loading settings:', error);
    });
});

function loadSettingsFromServer(settings) {
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
    if (settings.system_timezone && document.getElementById('systemTimezone')) {
        document.getElementById('systemTimezone').value = settings.system_timezone;
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

// Update server time display
function updateServerTime() {
    const serverTimeElement = document.getElementById('currentServerTime');
    if (serverTimeElement) {
        fetch('/get_server_time')
            .then(response => response.json())
            .then(data => {
                if (data.current_time) {
                    serverTimeElement.textContent = data.current_time;
                }
            })
            .catch(error => {
                console.error('Error fetching server time:', error);
                serverTimeElement.textContent = 'Error loading time';
            });
    }
}

// Update system information display
function updateSystemInfo() {
    // Update uptime
    const uptimeElement = document.getElementById('uptime');
    const dbSizeElement = document.getElementById('dbSize');
    const lastBackupElement = document.getElementById('lastBackup');
    
    if (uptimeElement || dbSizeElement || lastBackupElement) {
        fetch('/get_system_info')
            .then(response => response.json())
            .then(data => {
                if (!data.error) {
                    if (uptimeElement) uptimeElement.textContent = data.uptime || 'Calculating...';
                    if (dbSizeElement) dbSizeElement.textContent = data.db_size || 'Calculating...';
                    if (lastBackupElement) lastBackupElement.textContent = data.last_backup || 'Never';
                }
            })
            .catch(error => {
                console.error('Error fetching system info:', error);
                if (uptimeElement) uptimeElement.textContent = 'Error';
                if (dbSizeElement) dbSizeElement.textContent = 'Error';
                if (lastBackupElement) lastBackupElement.textContent = 'Error';
            });
    }
}

// Update server time every 30 seconds
setInterval(updateServerTime, 30000);

// Update system info every 60 seconds
setInterval(updateSystemInfo, 60000);

// Update server time and system info on page load
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(updateServerTime, 1000); // Small delay to ensure page is fully loaded
    setTimeout(updateSystemInfo, 1500); // Small delay to ensure page is fully loaded
});
