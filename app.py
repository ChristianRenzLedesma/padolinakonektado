from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import smtplib
import pytz
import secrets
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image

app = Flask(__name__)
app.secret_key = 'padolina_secret_key_2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Timezone configuration
TIMEZONE = pytz.timezone('Asia/Manila')  # Philippines timezone
app.config['TIMEZONE'] = TIMEZONE

# Track application start time for uptime calculation
import time
app_start_time = time.time()

def get_current_time():
    """Get current time in the configured timezone"""
    return datetime.now(TIMEZONE)

def format_datetime_local(dt):
    """Format datetime in local timezone"""
    if dt is None:
        return ""
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        # If datetime is naive, assume it's in local timezone
        dt = TIMEZONE.localize(dt)
    elif hasattr(dt, 'tzinfo'):
        # Convert to local timezone if it has timezone info
        dt = dt.astimezone(TIMEZONE)
    return dt.strftime('%B %d, %Y at %I:%M %p')

# SMTP Configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'christianrenzledesma210@gmail.com'
SMTP_PASSWORD = 'fwfy vzhf fnia amnh'
FROM_EMAIL = 'christianrenzledesma210@gmail.com'

# Database configuration
def get_db_connection():
    conn = sqlite3.connect('padolinakonektado.db')
    conn.row_factory = sqlite3.Row
    return conn

# File upload helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def process_profile_picture(file_path, user_id):
    """Process and optimize profile picture for better resolution and performance"""
    try:
        # Open the image
        img = Image.open(file_path)
        
        # Convert to RGB if necessary (for PNG with transparency)
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            if img.mode == 'RGBA':
                background.paste(img, mask=img.split()[-1])
                img = background
            else:
                img = img.convert('RGB')
        
        # Resize to optimal size (maintain aspect ratio)
        max_size = (500, 500)
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Create square image (center crop if necessary)
        width, height = img.size
        if width != height:
            min_dim = min(width, height)
            left = (width - min_dim) // 2
            top = (height - min_dim) // 2
            right = (width + min_dim) // 2
            bottom = (height + min_dim) // 2
            img = img.crop((left, top, right, bottom))
        
        # Save with high quality
        processed_filename = f"{user_id}_processed_{os.path.basename(file_path)}"
        processed_path = os.path.join(os.path.dirname(file_path), processed_filename)
        
        # Save as JPEG with high quality
        img.save(processed_path, 'JPEG', quality=95, optimize=True)
        
        # Remove original file
        os.remove(file_path)
        
        return processed_filename
    except Exception as e:
        print(f"Error processing image: {e}")
        # If processing fails, return original filename
        return os.path.basename(file_path)

def get_profile_picture_url(profile_picture):
    """Get the URL for profile picture with fallback to default"""
    if profile_picture and profile_picture.strip():
        return url_for('static', filename=f'uploads/profile_pics/{profile_picture}')
    else:
        return url_for('static', filename='img/default_profile.png')

def wants_json_response():
    return (
        request.is_json or
        request.accept_mimetypes.best == 'application/json' or
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    )

def parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {'1', 'true', 'on', 'yes', 'active'}

def admin_required(view_func):
    """Decorator to restrict routes to authenticated admins."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'admin':
            if wants_json_response():
                return jsonify({'success': False, 'message': 'Access denied'}), 403
            flash('Access denied! Admin privileges required.', 'danger')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped_view

def user_action_response(success, message, status_code=200, extra=None, category=None):
    """Return JSON or flash+redirect depending on request context."""
    if wants_json_response():
        payload = {'success': success, 'message': message}
        if extra:
            payload.update(extra)
        return jsonify(payload), status_code
    flash(message, category or ('success' if success else 'danger'))
    return redirect(url_for('user_management'))

# Helper function for logging user activities
def log_user_activity(user_id, action, details, ip_address=None, target_user_id=None):
    """Log user activity to database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO user_activity_log (admin_id, target_user_id, action, details)
            VALUES (?, ?, ?, ?)
        """, (user_id, target_user_id, action, details))
        
        conn.commit()
    except Exception as e:
        print(f"Error logging user activity: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

# Initialize database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create tables
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            user_type TEXT DEFAULT 'resident',
            address TEXT,
            phone TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER,
            is_published BOOLEAN DEFAULT 1,
            is_important BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            event_date DATE,
            event_time TIME,
            location TEXT,
            is_published BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Create the concerns table with all required columns
        CREATE TABLE IF NOT EXISTS concerns_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT,
            image_path TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        -- Copy data from old table if it exists
        BEGIN;
        INSERT INTO concerns_new (id, user_id, title, description, location, status, created_at, updated_at)
        SELECT id, user_id, title, description, location, status, created_at, updated_at FROM concerns;
        COMMIT;

        -- Drop the old table and rename the new one
        DROP TABLE IF EXISTS concerns;
        ALTER TABLE concerns_new RENAME TO concerns;
        
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS user_activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            target_user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users (id),
            FOREIGN KEY (target_user_id) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            user_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            login_status TEXT DEFAULT 'success',
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Create default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed_password = generate_password_hash('admin123')
        cursor.execute('''
            INSERT INTO users (username, email, password, first_name, last_name, user_type, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@padolinakonektado.ph', hashed_password, 'System', 'Administrator', 'admin', 1))
    
    conn.commit()
    conn.close()

# OTP Functions
def generate_otp():
    """Generate a 6-digit OTP code"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(to_email, otp_code, user_name):
    """Send OTP email using SMTP"""
    try:
        # Create message
        subject = "Password Reset OTP - PadolinaKonektado"
        
        # HTML email content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #2d6bc2 0%, #1a365d 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-box {{ background: #e6a400; color: #1a202c; padding: 15px 30px; border-radius: 10px; font-size: 32px; font-weight: bold; text-align: center; letter-spacing: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>PadolinaKonektado</h2>
                    <p>Community Connection Portal</p>
                </div>
                <div class="content">
                    <h3>Hello {user_name},</h3>
                    <p>You requested to reset your password for your PadolinaKonektado account.</p>
                    <p>Use the following OTP code to verify your identity:</p>
                    
                    <div class="otp-box">
                        {otp_code}
                    </div>
                    
                    <div class="warning">
                        <strong>Important:</strong> This OTP code will expire in 10 minutes for security reasons.
                    </div>
                    
                    <p>If you didn't request this reset, please ignore this email.</p>
                    <div class="footer">
                        <p>Barangay Padolina &copy; 2025. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text content for non-HTML email clients
        text_content = f"""
        Password Reset OTP - PadolinaKonektado
        
        Hello {user_name},
        
        You requested to reset your password for your PadolinaKonektado account.
        
        Your OTP code is: {otp_code}
        
        This code will expire in 10 minutes for security reasons.
        
        If you didn't request this reset, please ignore this email.
        
        Barangay Padolina © 2025. All rights reserved.
        """
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        
        # Attach both HTML and plain text versions
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        print(f"OTP email sent to {to_email}")
        return True
        
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        return False

# Custom filter for datetime formatting - TIMEZONE AWARE VERSION
@app.template_filter('format_datetime')
def format_datetime(value, format='%B %d, %Y at %I:%M %p'):
    if not value:
        return ""
    
    # Handle string input from database
    if isinstance(value, str):
        try:
            # Try different datetime formats that SQLite might return
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f%z']:
                try:
                    value = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
            else:
                # If we get here, no format matched
                return value
        except Exception as e:
            print(f"Error parsing datetime string '{value}': {e}")
            return value  # Return original string if parsing fails
    
    # If we have a datetime object, format it with timezone
    try:
        return format_datetime_local(value)
    except (AttributeError, ValueError) as e:
        print(f"Error formatting datetime {value}: {e}")
        return str(value)  # Return string representation as fallback

# Function to get community statistics
def get_community_stats():
    """Function to get community statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total residents (active users)
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE is_active = 1 AND user_type = 'resident'")
        total_residents = cursor.fetchone()[0]
        
        # Get total concerns
        cursor.execute("SELECT COUNT(*) as total FROM concerns")
        total_concerns = cursor.fetchone()[0]
        
        # Get total events
        cursor.execute("SELECT COUNT(*) as total FROM events WHERE is_published = 1")
        total_events = cursor.fetchone()[0]
        
        # Get total announcements
        cursor.execute("SELECT COUNT(*) as total FROM announcements WHERE is_published = 1")
        total_announcements = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_residents': total_residents,
            'total_concerns': total_concerns,
            'total_events': total_events,
            'total_announcements': total_announcements
        }
    except Exception as e:
        # Return default values if there's an error
        print(f"Error getting community stats: {e}")
        return {
            'total_residents': 0,
            'total_concerns': 0,
            'total_events': 0,
            'total_announcements': 0
        }

def get_public_stats():
    """Function to get public community statistics for home page"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total residents (active users)
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE is_active = 1 AND user_type = 'resident'")
        total_residents = cursor.fetchone()[0]
        
        # Get resolved concerns (status = 'resolved')
        cursor.execute("SELECT COUNT(*) as total FROM concerns WHERE status = 'resolved'")
        resolved_concerns = cursor.fetchone()[0]
        
        # Get total events
        cursor.execute("SELECT COUNT(*) as total FROM events WHERE is_published = 1")
        total_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_residents': total_residents,
            'resolved_concerns': resolved_concerns,
            'total_events': total_events
        }
    except Exception as e:
        # Return default values if there's an error
        print(f"Error getting public stats: {e}")
        return {
            'total_residents': 0,
            'resolved_concerns': 0,
            'total_events': 0
        }

# Context Processor for Community Stats
@app.context_processor
def inject_community_stats():
    """Inject community stats into all templates"""
    if session.get('user_id'):
        stats = get_community_stats()
        return {
            'total_residents': stats['total_residents'],
            'total_concerns': stats['total_concerns'],
            'total_events': stats['total_events'],
            'total_announcements': stats['total_announcements']
        }
    return {}

@app.context_processor
def inject_announcement_count():
    """Make announcement count available to all templates - SQLite3 version"""
    announcement_count = 0
    
    if 'user_id' in session and 'user_type' in session:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if session['user_type'] == 'admin':
                # For admin: show recent announcements (last 7 days) - SQLite3 syntax
                cursor.execute("""
                    SELECT COUNT(*) as new_announcements 
                    FROM announcements 
                    WHERE is_published = 1 
                    AND datetime(created_at) >= datetime('now', '-7 days')
                """)
            else:
                # For residents: show recent announcements (last 7 days) - SQLite3 syntax
                cursor.execute("""
                    SELECT COUNT(*) as new_announcements 
                    FROM announcements 
                    WHERE is_published = 1 
                    AND datetime(created_at) >= datetime('now', '-7 days')
                """)
            
            result = cursor.fetchone()
            announcement_count = result[0] if result else 0
            
        except Exception as e:
            print(f"Error getting announcement count: {e}")
            announcement_count = 0
        finally:
            if 'conn' in locals():
                conn.close()
    
    return {'announcement_count': announcement_count}

"""        ROUTES          """

@app.route('/report_concern')
def report_concern():
    """Display the report concern form and list of concerns - protected"""
    if 'user_id' not in session:
        flash('Please login to report a concern.', 'danger')
        return redirect(url_for('login'))
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user info
        cursor.execute("SELECT id, first_name, last_name FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))
        
        # Get all concerns for this user
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name 
            FROM concerns c
            JOIN users u ON c.user_id = u.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        """, (session['user_id'],))
        
        concerns = []
        for row in cursor.fetchall():
            concern = dict(row)
            # Ensure image_path is properly formatted
            if concern.get('image_path'):
                concern['image_path'] = concern['image_path'].replace('\\', '/')
                if concern['image_path'].startswith('static/'):
                    concern['image_path'] = concern['image_path'][7:]  # Remove 'static/' prefix
            concerns.append(concern)
        
        return render_template('report_concern.html', 
                            concerns=concerns, 
                            session=session)
        
    except Exception as e:
        print(f"Error in report_concern: {str(e)}")
        flash('An error occurred while loading the page. Please try again.', 'danger')
        return render_template('report_concern.html', concerns=[])
        
    finally:
        if conn:
            conn.close()

@app.route('/uploads/concerns/<filename>')
def serve_concern_image(filename):
    """Serve concern images from the uploads/concerns directory"""
    try:
        # Clean up the filename
        filename = secure_filename(filename)
        
        # Define the uploads directory
        uploads_dir = os.path.join(app.root_path, 'uploads', 'concerns')
        
        # Full path to the image
        full_path = os.path.join(uploads_dir, filename)
        
        # Check if file exists
        if not os.path.exists(full_path):
            print(f"Image not found: {full_path}")  # Debug log
            return send_from_directory(
                os.path.join(app.root_path, 'static', 'img'),
                'default_concern.png',
                mimetype='image/png',
                as_attachment=False
            )
        
        # Serve the image
        return send_from_directory(
            uploads_dir,
            filename,
            as_attachment=False,
            max_age=3600  # Cache for 1 hour
        )
    except Exception as e:
        print(f"Error serving image {filename}: {str(e)}")  # Debug log
        # Try to serve default image on error
        try:
            return send_from_directory(
                os.path.join(app.root_path, 'static', 'img'),
                'default_concern.png',
                mimetype='image/png',
                as_attachment=False
            )
        except Exception as e:
            print(f"Error serving default image: {str(e)}")  # Debug log
            abort(404)
@app.route('/events')
def events():
    return render_template('events.html', title='Events')

@app.route('/community_forum')
def community_forum():
    return render_template('community_forum.html', title='Community Forum')

@app.route('/user_management')
def user_management():
    """Comprehensive user management dashboard - admin only"""
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))

    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', 'all')
    status_filter = request.args.get('status', 'all')
    sort = request.args.get('sort', 'newest')
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    per_page = 10

    sort_map = {
        'newest': 'created_at DESC',
        'oldest': 'created_at ASC',
        'name': 'last_name ASC, first_name ASC',
        'recent_login': 'CASE WHEN last_login IS NULL THEN 1 ELSE 0 END, last_login DESC'
    }

    query_conditions = []
    params = []

    if search:
        like = f"%{search.lower()}%"
        query_conditions.append("(LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(username) LIKE ?)")
        params.extend([like, like, like, like])

    if role_filter in ('admin', 'resident'):
        query_conditions.append('user_type = ?')
        params.append(role_filter)

    if status_filter in ('active', 'inactive'):
        query_conditions.append('is_active = ?')
        params.append(1 if status_filter == 'active' else 0)

    base_query = 'FROM users'
    if query_conditions:
        base_query_where = ' WHERE ' + ' AND '.join(query_conditions)
    else:
        base_query_where = ''

    order_clause = sort_map.get(sort, sort_map['newest'])

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total for current filter set
        cursor.execute(f'SELECT COUNT(*) as total {base_query} {base_query_where}', params)
        total_filtered = cursor.fetchone()['total']

        # Fetch current page
        offset = (page - 1) * per_page
        cursor.execute(
            f'SELECT * {base_query} {base_query_where} ORDER BY {order_clause} LIMIT ? OFFSET ?',
            params + [per_page, offset],
        )
        users = cursor.fetchall()

        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']

        cursor.execute('SELECT COUNT(*) as total FROM users WHERE is_active = 1')
        active_users = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM users WHERE created_at >= datetime('now', '-30 days')")
        new_this_month = cursor.fetchone()['total']

        cursor.execute('SELECT user_type, COUNT(*) as total FROM users GROUP BY user_type')
        role_breakdown = {row['user_type']: row['total'] for row in cursor.fetchall()}

        stats = {
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': total_users - active_users,
            'admins': role_breakdown.get('admin', 0),
            'residents': role_breakdown.get('resident', 0),
            'new_this_month': new_this_month,
            'total_filtered': total_filtered,
        }

    except Exception as e:
        print(f"Error loading user management: {e}")
        flash('Failed to load user data. Please try again.', 'danger')
        users = []
        stats = {
            'total_users': 0,
            'active_users': 0,
            'inactive_users': 0,
            'admins': 0,
            'residents': 0,
            'new_this_month': 0,
            'total_filtered': 0,
        }
    finally:
        if 'conn' in locals():
            conn.close()

    filters = {
        'search': search,
        'role': role_filter,
        'status': status_filter,
        'sort': sort,
    }

    total_pages = (stats['total_filtered'] + per_page - 1) // per_page if per_page else 1
    pagination = {
        'page': page,
        'per_page': per_page,
        'total_filtered': stats['total_filtered'],
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
    }

    return render_template(
        'user_management.html',
        title='User Management',
        users=users,
        stats=stats,
        filters=filters,
        pagination=pagination,
    )

@app.route('/user_management/export_csv')
@admin_required
def export_users_csv():
    """Export filtered users to CSV."""
    import csv
    from io import StringIO

    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', 'all')
    status_filter = request.args.get('status', 'all')
    sort = request.args.get('sort', 'newest')

    sort_map = {
        'newest': 'created_at DESC',
        'oldest': 'created_at ASC',
        'name': 'last_name ASC, first_name ASC',
        'recent_login': 'CASE WHEN last_login IS NULL THEN 1 ELSE 0 END, last_login DESC',
    }

    query_conditions = []
    params = []

    if search:
        like = f"%{search.lower()}%"
        query_conditions.append(
            "(LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(username) LIKE ?)"
        )
        params.extend([like, like, like, like])

    if role_filter in ('admin', 'resident'):
        query_conditions.append('user_type = ?')
        params.append(role_filter)

    if status_filter in ('active', 'inactive'):
        query_conditions.append('is_active = ?')
        params.append(1 if status_filter == 'active' else 0)

    base_query = 'SELECT * FROM users'
    if query_conditions:
        base_query += ' WHERE ' + ' AND '.join(query_conditions)

    order_clause = sort_map.get(sort, sort_map['newest'])
    base_query += f' ORDER BY {order_clause}'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(base_query, params)
        users = cursor.fetchall()
    except Exception as e:
        print(f"Error exporting users CSV: {e}")
        flash('Failed to export users.', 'danger')
        return redirect(url_for('user_management'))
    finally:
        if 'conn' in locals():
            conn.close()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow([
        'ID',
        'Username',
        'Email',
        'First Name',
        'Last Name',
        'Role',
        'Address',
        'Phone',
        'Active',
        'Created At',
        'Last Login',
    ])

    for u in users:
        cw.writerow([
            u['id'],
            u['username'],
            u['email'],
            u['first_name'],
            u['last_name'],
            u['user_type'],
            u['address'],
            u['phone'],
            1 if u['is_active'] else 0,
            u['created_at'],
            u['last_login'],
        ])

    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=users_export.csv',
        },
    )

@app.route('/user_management/print')
@admin_required
def user_management_print():
    """Printable view of filtered users."""
    # Reuse same filtering logic but without pagination
    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', 'all')
    status_filter = request.args.get('status', 'all')
    sort = request.args.get('sort', 'newest')

    sort_map = {
        'newest': 'created_at DESC',
        'oldest': 'created_at ASC',
        'name': 'last_name ASC, first_name ASC',
        'recent_login': 'CASE WHEN last_login IS NULL THEN 1 ELSE 0 END, last_login DESC',
    }

    query_conditions = []
    params = []

    if search:
        like = f"%{search.lower()}%"
        query_conditions.append(
            "(LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(username) LIKE ?)"
        )
        params.extend([like, like, like, like])

    if role_filter in ('admin', 'resident'):
        query_conditions.append('user_type = ?')
        params.append(role_filter)

    if status_filter in ('active', 'inactive'):
        query_conditions.append('is_active = ?')
        params.append(1 if status_filter == 'active' else 0)

    base_query = 'SELECT * FROM users'
    if query_conditions:
        base_query += ' WHERE ' + ' AND '.join(query_conditions)

    order_clause = sort_map.get(sort, sort_map['newest'])
    base_query += f' ORDER BY {order_clause}'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(base_query, params)
        users = cursor.fetchall()
    except Exception as e:
        print(f"Error loading users for print: {e}")
        users = []
    finally:
        if 'conn' in locals():
            conn.close()

    return render_template('user_management_print.html', users=users)

@app.route('/reports')
@admin_required
def reports():
    return render_template('reports.html', title='Reports')

@app.route('/get_server_time')
def get_server_time():
    """Get current server time in configured timezone"""
    if 'user_id' not in session:
        return jsonify({'error': 'Access denied'}), 403
    
    current_time = get_current_time()
    return jsonify({
        'current_time': current_time.strftime('%B %d, %Y at %I:%M:%S %p %Z'),
        'timezone': str(TIMEZONE)
    })

@app.route('/get_system_info')
def get_system_info():
    """Get system information including uptime and database stats"""
    if 'user_id' not in session:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size_result = cursor.fetchone()
        db_size_bytes = db_size_result[0] if db_size_result else 0
        db_size_mb = round(db_size_bytes / (1024 * 1024), 2)
        
        # Get last backup time
        cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'last_backup'")
        last_backup_row = cursor.fetchone()
        if last_backup_row and last_backup_row[0]:
            last_backup = last_backup_row[0]
            # If stored in database format, convert to display format
            if len(last_backup) == 19 and last_backup[10] == ' ':  # Format: 'YYYY-MM-DD HH:MM:SS'
                try:
                    dt = datetime.strptime(last_backup, '%Y-%m-%d %H:%M:%S')
                    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
                        dt = TIMEZONE.localize(dt)
                    elif hasattr(dt, 'tzinfo'):
                        dt = dt.astimezone(TIMEZONE)
                    last_backup = dt.strftime('%B %d, %Y at %I:%M %p')
                except:
                    pass  # Keep original if parsing fails
        else:
            last_backup = "Never"
        
        # Get user count
        cursor.execute("SELECT COUNT(*) as count FROM users")
        user_count = cursor.fetchone()[0]
        
        # Get concerns count
        cursor.execute("SELECT COUNT(*) as count FROM concerns")
        concerns_count = cursor.fetchone()[0]
        
        conn.close()
        
        # Calculate uptime (app start time)
        import time
        uptime_seconds = time.time() - app_start_time
        uptime_days = int(uptime_seconds // 86400)
        uptime_hours = int((uptime_seconds % 86400) // 3600)
        uptime_minutes = int((uptime_seconds % 3600) // 60)
        
        uptime_str = f"{uptime_days}d {uptime_hours}h {uptime_minutes}m"
        
        return jsonify({
            'uptime': uptime_str,
            'db_size': f"{db_size_mb} MB",
            'last_backup': last_backup,
            'user_count': user_count,
            'concerns_count': concerns_count,
            'system_version': '1.0.0'
        })
        
    except Exception as e:
        print(f"Error getting system info: {e}")
        return jsonify({'error': 'Failed to get system info'}), 500

@app.route('/backup_database', methods=['POST'])
def backup_database():
    """Perform database backup"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        import shutil
        from datetime import datetime
        
        # Create backup directory if it doesn't exist
        backup_dir = os.path.join(os.getcwd(), 'backups')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Create backup filename with timestamp
        timestamp = get_current_time().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"padolina_backup_{timestamp}.db"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Copy the database file
        db_path = 'padolinakonektado.db'
        if not os.path.exists(db_path):
            print(f"Database file not found: {db_path}")
            return jsonify({'success': False, 'message': f'Database file not found: {db_path}'}), 404
        
        print(f"Attempting to copy {db_path} to {backup_path}")
        shutil.copy2(db_path, backup_path)
        print(f"Successfully copied database to {backup_path}")
        
        # Update last backup time in settings
        conn = get_db_connection()
        cursor = conn.cursor()
        backup_time_str = get_current_time().strftime('%B %d, %Y at %I:%M %p')
        cursor.execute("""
            INSERT OR REPLACE INTO system_settings 
            (setting_key, setting_value, updated_at) 
            VALUES (?, ?, ?)
        """, ('last_backup', backup_time_str, get_current_time()))
        conn.commit()
        conn.close()
        
        # Log the backup
        log_user_activity(
            session['user_id'],
            'database_backup',
            f'Database backed up to {backup_filename}',
            request.remote_addr
        )
        
        return jsonify({
            'success': True, 
            'message': f'Backup completed successfully! File saved as {backup_filename}'
        })
        
    except Exception as e:
        print(f"Error during backup: {e}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Database file exists: {os.path.exists('padolinakonektado.db')}")
        return jsonify({'success': False, 'message': f'Backup failed: {str(e)}'}), 500

@app.route('/optimize_database', methods=['POST'])
def optimize_database():
    """Optimize database"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Run VACUUM to optimize database
        cursor.execute("VACUUM")
        
        # Update statistics
        cursor.execute("ANALYZE")
        
        conn.commit()
        conn.close()
        
        # Log the optimization
        log_user_activity(
            session['user_id'],
            'database_optimize',
            'Database optimized successfully',
            request.remote_addr
        )
        
        return jsonify({'success': True, 'message': 'Database optimized successfully!'})
        
    except Exception as e:
        print(f"Error during optimization: {e}")
        return jsonify({'success': False, 'message': f'Optimization failed: {str(e)}'}), 500

@app.route('/system_settings', methods=['GET', 'POST'])
def system_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        setting_type = request.form.get('setting_type')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if setting_type == 'system':
                # Save system settings
                system_name = request.form.get('system_name', 'Padolina Konektado')
                system_description = request.form.get('system_description', 'Community Management System')
                admin_email = request.form.get('admin_email', 'admin@padolina.com')
                system_timezone = request.form.get('system_timezone', 'Asia/Manila')
                user_registration = request.form.get('user_registration') == 'on'
                email_verification = request.form.get('email_verification') == 'on'
                admin_approval = request.form.get('admin_approval') == 'on'
                items_per_page = request.form.get('items_per_page', '25')
                auto_save = request.form.get('auto_save') == 'on'
                
                # Update global timezone variable
                global TIMEZONE
                try:
                    TIMEZONE = pytz.timezone(system_timezone)
                    app.config['TIMEZONE'] = TIMEZONE
                except Exception as e:
                    print(f"Error setting timezone: {e}")
                    # Keep existing timezone if invalid
                
                # Update or insert system settings
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('system_name', system_name, get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('system_description', system_description, get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('admin_email', admin_email, get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('system_timezone', system_timezone, get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('user_registration', str(user_registration), get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('email_verification', str(email_verification), get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('admin_approval', str(admin_approval), get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('items_per_page', items_per_page, get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('auto_save', str(auto_save), get_current_time()))
                
                conn.commit()
                flash('System settings saved successfully!', 'success')
                
            elif setting_type == 'security':
                # Save security settings
                min_password_length = request.form.get('min_password_length', '8')
                password_expiry = request.form.get('password_expiry', '90')
                require_special_chars = request.form.get('require_special_chars') == 'on'
                require_numbers = request.form.get('require_numbers') == 'on'
                session_timeout = request.form.get('session_timeout', '30')
                remember_me = request.form.get('remember_me') == 'on'
                two_factor_auth = request.form.get('two_factor_auth') == 'on'
                login_attempts = request.form.get('login_attempts') == 'on'
                max_login_attempts = request.form.get('max_login_attempts', '5')
                
                # Save security settings
                security_settings = {
                    'min_password_length': min_password_length,
                    'password_expiry': password_expiry,
                    'require_special_chars': str(require_special_chars),
                    'require_numbers': str(require_numbers),
                    'session_timeout': session_timeout,
                    'remember_me': str(remember_me),
                    'two_factor_auth': str(two_factor_auth),
                    'login_attempts': str(login_attempts),
                    'max_login_attempts': max_login_attempts
                }
                
                for key, value in security_settings.items():
                    cursor.execute("""
                        INSERT OR REPLACE INTO system_settings 
                        (setting_key, setting_value, updated_at) 
                        VALUES (?, ?, ?)
                    """, (f'security_{key}', value, get_current_time()))
                
                conn.commit()
                flash('Security settings saved successfully!', 'success')
                
            elif setting_type == 'email':
                # Save email settings
                smtp_server = request.form.get('smtp_server')
                smtp_port = request.form.get('smtp_port', '587')
                smtp_username = request.form.get('smtp_username')
                smtp_password = request.form.get('smtp_password')
                smtp_tls = request.form.get('smtp_tls') == 'on'
                from_email = request.form.get('from_email')
                from_name = request.form.get('from_name')
                
                # Save email settings
                email_settings = {
                    'smtp_server': smtp_server,
                    'smtp_port': smtp_port,
                    'smtp_username': smtp_username,
                    'smtp_password': smtp_password,
                    'smtp_tls': str(smtp_tls),
                    'from_email': from_email,
                    'from_name': from_name
                }
                
                for key, value in email_settings.items():
                    cursor.execute("""
                        INSERT OR REPLACE INTO system_settings 
                        (setting_key, setting_value, updated_at) 
                        VALUES (?, ?, ?)
                    """, (f'email_{key}', value, get_current_time()))
                
                conn.commit()
                flash('Email settings saved successfully!', 'success')
                
            elif setting_type == 'backup':
                # Save backup settings
                auto_backup = request.form.get('auto_backup') == 'on'
                backup_frequency = request.form.get('backup_frequency', 'weekly')
                backup_retention = request.form.get('backup_retention', '30')
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('auto_backup', str(auto_backup), get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('backup_frequency', backup_frequency, get_current_time()))
                
                cursor.execute("""
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, updated_at) 
                    VALUES (?, ?, ?)
                """, ('backup_retention', backup_retention, get_current_time()))
                
                conn.commit()
                flash('Backup settings saved successfully!', 'success')
                
        except Exception as e:
            print(f"Error saving settings: {e}")
            flash('Failed to save settings!', 'danger')
        finally:
            if 'conn' in locals():
                conn.close()
        
        # Return JSON for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Settings saved successfully!'})
        
        return redirect(url_for('system_settings'))
    
    # Load current settings for GET request
    settings = {}
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_key, setting_value FROM system_settings")
        for row in cursor.fetchall():
            settings[row['setting_key']] = row['setting_value']
    except Exception as e:
        print(f"Error loading settings: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
    
    # Return JSON for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'settings': settings})
    
    return render_template('system_settings.html', title='System Settings', settings=settings)

@app.route('/news')
def news():
    return render_template('news.html', title='News & Updates')

@app.route('/event_calendar')
def event_calendar():
    return render_template('event_calendar.html', title='Event Calendar')

@app.route('/directory')
def directory():
    return render_template('directory.html', title='Directory')

@app.route('/otp_verification')
def otp_verification():
    """OTP verification page"""
    email = request.args.get('email', '')
    return render_template('otp_verification.html', email=email)

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    """Handle forgot password requests - Send OTP"""
    email = request.json.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email exists
        cursor.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,))
        user = cursor.fetchone()
        
        if user:
            # Generate OTP
            otp_code = generate_otp()
            
            # Calculate expiration time (10 minutes from now)
            expires_at = get_current_time() + timedelta(minutes=10)
            
            # Store OTP in database
            cursor.execute("""
                INSERT INTO otp_codes (user_id, email, otp_code, expires_at) 
                VALUES (?, ?, ?, ?)
            """, (user['id'], email, otp_code, expires_at))
            
            conn.commit()
            
            # Send OTP email
            user_name = f"{user['first_name']} {user['last_name']}"
            email_sent = send_otp_email(user['email'], otp_code, user_name)
            
            if email_sent:
                return jsonify({
                    'success': True, 
                    'message': 'OTP has been sent to your email. Please check your inbox.',
                    'email': email  # Return email for the next step
                })
            else:
                return jsonify({
                    'success': False, 
                    'message': 'Failed to send OTP. Please try again later.'
                }), 500
        else:
            # RETURN ERROR WHEN EMAIL NOT FOUND
            return jsonify({
                'success': False, 
                'message': 'No account found with this email address. Please check your email or register for a new account.'
            }), 404
            
    except Exception as e:
        print(f"Error in forgot_password: {e}")
        return jsonify({
            'success': False, 
            'message': 'An error occurred. Please try again.'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    """Verify OTP and proceed to password reset"""
    email = request.json.get('email')
    otp_code = request.json.get('otp_code')
    
    print(f"OTP Verification Attempt - Email: {email}, OTP: {otp_code}")  # DEBUG
    
    if not email or not otp_code:
        print("Missing email or OTP")  # DEBUG
        return jsonify({'success': False, 'message': 'Email and OTP are required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if OTP is valid and not expired
        cursor.execute("""
            SELECT oc.*, u.id as user_id, u.first_name, u.last_name 
            FROM otp_codes oc 
            JOIN users u ON oc.user_id = u.id 
            WHERE oc.email = ? AND oc.otp_code = ? AND oc.used = 0 AND oc.expires_at > datetime('now')
        """, (email, otp_code))
        
        otp_data = cursor.fetchone()
        
        print(f"OTP Query Result: {otp_data}")  # DEBUG
        
        if otp_data:
            print("OTP is valid")  # DEBUG
            # Mark OTP as used
            cursor.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_data['id'],))
            
            # Generate reset token for password reset
            reset_token = secrets.token_urlsafe(32)
            expires_at = get_current_time() + timedelta(hours=1)
            
            # Store reset token
            cursor.execute("""
                INSERT INTO password_reset_tokens (user_id, token, expires_at) 
                VALUES (?, ?, ?)
            """, (otp_data['user_id'], reset_token, expires_at))
            
            conn.commit()
            
            print(f"Reset token generated: {reset_token}")  # DEBUG
            
            return jsonify({
                'success': True,
                'message': 'OTP verified successfully!',
                'reset_token': reset_token
            })
        else:
            print("OTP is invalid or expired")  # DEBUG
            # Additional debugging - check what's in the database
            cursor.execute("SELECT * FROM otp_codes WHERE email = ? ORDER BY created_at DESC LIMIT 1", (email,))
            latest_otp = cursor.fetchone()
            print(f"Latest OTP in DB: {latest_otp}")  # DEBUG
            
            return jsonify({
                'success': False,
                'message': 'Invalid or expired OTP. Please try again.'
            }), 400
            
    except Exception as e:
        print(f"Error in verify_otp: {e}")  # DEBUG
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset with token"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if token is valid and not expired
        cursor.execute("""
            SELECT pt.*, u.email, u.first_name, u.last_name 
            FROM password_reset_tokens pt 
            JOIN users u ON pt.user_id = u.id 
            WHERE pt.token = ? AND pt.used = 0 AND pt.expires_at > datetime('now')
        """, (token,))
        
        token_data = cursor.fetchone()
        
        if not token_data:
            flash('Invalid or expired reset token. Please request a new password reset.', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if new_password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return render_template('reset_password.html', token=token)
            
            if len(new_password) < 6:
                flash('Password must be at least 6 characters!', 'danger')
                return render_template('reset_password.html', token=token)
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = ?, updated_at = ? WHERE id = ?", 
                         (hashed_password, get_current_time(), token_data['user_id']))
            
            # Mark token as used
            cursor.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
            
            conn.commit()
            
            flash('Password reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token, email=token_data['email'])
        
    except Exception as e:
        print(f"Error in reset_password: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('login'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/')
def home():
    """Home page - public access"""
    stats = get_public_stats()
    return render_template('home.html', 
                         total_residents=stats['total_residents'],
                         resolved_concerns=stats['resolved_concerns'],
                         total_events=stats['total_events'])

@app.context_processor
def inject_profile_picture_url():
    """Make profile picture URL function available in templates"""
    return dict(get_profile_picture_url=get_profile_picture_url)

@app.route('/about')
def about():
    """About page - public access"""
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page - public access"""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # Here you can save the contact form to database or send email
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO contact_messages (name, email, subject, message) 
                VALUES (?, ?, ?, ?)""",
                (name, email, subject, message)
            )
            conn.commit()
            flash('Thank you for your message! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            print(f"Error saving contact message: {e}")
            flash('Sorry, there was an error sending your message. Please try again.', 'danger')
        finally:
            if 'conn' in locals():
                conn.close()
    
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - public access"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, username, email, password, first_name, last_name, user_type, profile_picture FROM users WHERE username = ? AND is_active = 1", (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['first_name'] = user['first_name']
                session['last_name'] = user['last_name']
                session['user_type'] = user['user_type']
                session['email'] = user['email']
                session['profile_picture'] = user['profile_picture']
                
                # Update last login
                cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (get_current_time(), user['id']))
                
                # Log successful login
                ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))
                user_agent = request.headers.get('User-Agent', 'Unknown')
                cursor.execute("""
                    INSERT INTO login_logs (user_id, username, user_type, ip_address, user_agent, login_status)
                    VALUES (?, ?, ?, ?, ?, 'success')
                """, (user['id'], user['username'], user['user_type'], ip_address, user_agent))
                
                # Also log to activity log
                log_user_activity(
                    user['id'],
                    'login',
                    f'User {user["username"]} logged in successfully',
                    ip_address
                )
                
                conn.commit()
                
                flash(f'Welcome back, {user["first_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Log failed login attempt
                ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))
                user_agent = request.headers.get('User-Agent', 'Unknown')
                
                # Try to get user info even if password is wrong
                cursor.execute("SELECT id, username, user_type FROM users WHERE username = ?", (username,))
                failed_user = cursor.fetchone()
                
                if failed_user:
                    cursor.execute("""
                        INSERT INTO login_logs (user_id, username, user_type, ip_address, user_agent, login_status)
                        VALUES (?, ?, ?, ?, ?, 'failed')
                    """, (failed_user['id'], failed_user['username'], failed_user['user_type'], ip_address, user_agent))
                else:
                    cursor.execute("""
                        INSERT INTO login_logs (user_id, username, user_type, ip_address, user_agent, login_status)
                        VALUES (?, ?, ?, ?, ?, 'failed')
                    """, (0, username, 'unknown', ip_address, user_agent))
                
                conn.commit()
                flash('Invalid username or password!', 'danger')
                
        except Exception as e:
            flash('Login failed! Please try again.', 'danger')
            print(f"Error: {e}")
        finally:
            if 'conn' in locals():
                conn.close()
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register page - public access"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        user_type = 'resident'  # Default to resident for registration
        address = request.form.get('address', '')
        phone = request.form.get('phone', '')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'danger')
            return render_template('register.html')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if username or email exists
            cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                flash('Username or email already exists!', 'danger')
                return render_template('register.html')
            
            # Hash password and create user
            hashed_password = generate_password_hash(password)
            cursor.execute(
                """INSERT INTO users (username, email, password, first_name, last_name, user_type, address, phone) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (username, email, hashed_password, first_name, last_name, user_type, address, phone)
            )
            
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Registration failed! Please try again.', 'danger')
            print(f"Error: {e}")
        finally:
            if 'conn' in locals():
                conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard route - redirects to appropriate dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Redirect to appropriate dashboard based on user type
    if session['user_type'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('resident_dashboard'))

@app.route('/dashboard/admin')
def admin_dashboard():
    """Admin dashboard - protected"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get statistics for admin
        cursor.execute("SELECT COUNT(*) as total_users FROM users WHERE is_active = 1")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as total_concerns FROM concerns")
        total_concerns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as pending_concerns FROM concerns WHERE status = 'pending'")
        pending_concerns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as total_announcements FROM announcements")
        total_announcements = cursor.fetchone()[0]
        
        # FIXED: Get unread announcements count for admin (SQLite3 syntax)
        cursor.execute("""
            SELECT COUNT(*) as new_announcements 
            FROM announcements 
            WHERE is_published = 1 
            AND datetime(created_at) >= datetime('now', '-7 days')
        """)
        announcement_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as total_events FROM events")
        total_events = cursor.fetchone()[0]
        
        # Get recent concerns with formatted datetime
        cursor.execute("""
            SELECT 
                c.id, 
                c.title, 
                c.status, 
                datetime(c.created_at) as created_at,  
                u.username, 
                c.description, 
                u.first_name, 
                u.last_name
            FROM concerns c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC
            LIMIT 5
        """)
        recent_concerns = cursor.fetchall()
        
        # Get recent users
        cursor.execute("SELECT * FROM users WHERE is_active = 1 ORDER BY created_at DESC LIMIT 5")
        recent_users = cursor.fetchall()
        
        # Get recent announcements
        cursor.execute("""
            SELECT a.id, a.title, a.created_at, u.first_name || ' ' || u.last_name as author_name
            FROM announcements a
            LEFT JOIN users u ON a.author_id = u.id
            ORDER BY a.created_at DESC
            LIMIT 5
        """)
        recent_announcements = cursor.fetchall()
        
    except Exception as e:
        print(f"Error: {e}")
        total_users = total_concerns = pending_concerns = total_announcements = total_events = 0
        announcement_count = 0  # Initialize announcement_count
        recent_concerns = []
        recent_users = []
        recent_announcements = []
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_concerns=total_concerns,
                         pending_concerns=pending_concerns,
                         total_announcements=total_announcements,
                         total_events=total_events,
                         recent_concerns=recent_concerns,
                         recent_users=recent_users,
                         recent_announcements=recent_announcements,
                         announcement_count=announcement_count)  # Pass announcement_count to template

@app.route('/dashboard/resident')
def resident_dashboard():
    """Resident dashboard - protected"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get recent announcements
        cursor.execute("""
            SELECT a.*, u.first_name, u.last_name 
            FROM announcements a 
            LEFT JOIN users u ON a.author_id = u.id 
            WHERE a.is_published = 1
            ORDER BY a.is_important DESC, a.created_at DESC LIMIT 5
        """)
        announcements = cursor.fetchall()
        
        # Get upcoming events
        cursor.execute("""
            SELECT * FROM events 
            WHERE event_date >= date('now') AND is_published = 1 
            ORDER BY event_date LIMIT 5
        """)
        events = cursor.fetchall()
        
        # Get user's concerns
        cursor.execute("SELECT COUNT(*) as concern_count FROM concerns WHERE user_id = ?", (session['user_id'],))
        concern_count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT * FROM concerns 
            WHERE user_id = ? 
            ORDER BY created_at DESC LIMIT 3
        """, (session['user_id'],))
        
        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]
        my_concerns = []
        
        for row in cursor.fetchall():
            # Convert row to dictionary using column names
            concern = dict(zip(columns, row))
            # Convert string dates to datetime objects
            if concern['created_at'] and isinstance(concern['created_at'], str):
                concern['created_at'] = datetime.strptime(concern['created_at'], '%Y-%m-%d %H:%M:%S')
            if concern['updated_at'] and isinstance(concern['updated_at'], str):
                concern['updated_at'] = datetime.strptime(concern['updated_at'], '%Y-%m-%d %H:%M:%S')
            my_concerns.append(concern)
        
        # Get user info for welcome message
        cursor.execute("SELECT first_name, last_name FROM users WHERE id = ?", (session['user_id'],))
        user_info = cursor.fetchone()
        
    except Exception as e:
        print(f"Error: {e}")
        announcements = []
        events = []
        concern_count = 0
        my_concerns = []
        user_info = {'first_name': 'User'}
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('resident_dashboard.html', 
                         announcements=announcements, 
                         events=events, 
                         concern_count=concern_count,
                         my_concerns=my_concerns,
                         user_info=user_info)

@app.route('/create_announcement', methods=['POST'])
def create_announcement():
    """Create new announcement - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_important = 1 if request.form.get('is_important') else 0
        
        if not title or not content:
            flash('Title and content are required!', 'danger')
            return redirect(url_for('announcements'))
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Use current local time instead of SQLite's CURRENT_TIMESTAMP
            current_time = get_current_time()
            
            cursor.execute("""
                INSERT INTO announcements (title, content, author_id, is_published, is_important, created_at)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (title, content, session['user_id'], is_important, current_time))
            
            announcement_id = cursor.lastrowid
            conn.commit()
            
            # Log announcement creation activity
            log_user_activity(
                session['user_id'],
                'announcement_created',
                f'Announcement created: {title} (ID: {announcement_id})',
                request.remote_addr
            )
            
            flash('Announcement published successfully!', 'success')
            
        except Exception as e:
            print(f"Error creating announcement: {e}")
            flash('Failed to create announcement!', 'danger')
        finally:
            if 'conn' in locals():
                conn.close()
    
    return redirect(url_for('announcements'))

@app.route('/delete_announcement/<int:announcement_id>', methods=['POST'])
def delete_announcement(announcement_id):
    """Delete announcement - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # First, get the announcement title for the flash message
        cursor.execute("SELECT title FROM announcements WHERE id = ?", (announcement_id,))
        announcement = cursor.fetchone()
        
        if announcement:
            # Delete the announcement
            cursor.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,))
            conn.commit()
            
            # Log announcement deletion activity
            log_user_activity(
                session['user_id'],
                'announcement_deleted',
                f'Announcement deleted: {announcement["title"]} (ID: {announcement_id})',
                request.remote_addr
            )
            
            flash(f'Announcement "{announcement["title"]}" has been deleted successfully!', 'success')
        else:
            flash('Announcement not found!', 'danger')
            
    except Exception as e:
        print(f"Error deleting announcement: {e}")
        flash('Failed to delete announcement!', 'danger')
    finally:
        if 'conn' in locals():
            conn.close()
    
    return redirect(url_for('announcements'))

@app.route('/edit_announcement/<int:announcement_id>', methods=['POST'])
def edit_announcement(announcement_id):
    """Edit announcement - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_important = 1 if request.form.get('is_important') else 0
        
        if not title or not content:
            flash('Title and content are required!', 'danger')
            return redirect(url_for('announcements'))
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Update the announcement
            cursor.execute("""
                UPDATE announcements 
                SET title = ?, content = ?, is_important = ?, updated_at = ?
                WHERE id = ?
            """, (title, content, is_important, get_current_time(), announcement_id))
            
            conn.commit()
            
            # Log announcement edit activity
            log_user_activity(
                session['user_id'],
                'announcement_edited',
                f'Announcement edited: {title} (ID: {announcement_id})',
                request.remote_addr
            )
            
            flash('Announcement updated successfully!', 'success')
            
        except Exception as e:
            print(f"Error updating announcement: {e}")
            flash('Failed to update announcement!', 'danger')
        finally:
            if 'conn' in locals():
                conn.close()
    
    return redirect(url_for('announcements'))

@app.route('/announcements')
def announcements():
    """Announcements page - protected"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT a.*, u.first_name, u.last_name 
            FROM announcements a 
            LEFT JOIN users u ON a.author_id = u.id 
            WHERE a.is_published = 1
            ORDER BY a.is_important DESC, a.created_at DESC
        """)
        announcements = cursor.fetchall()
        
    except Exception as e:
        print(f"Error: {e}")
        announcements = []
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('announcements.html', announcements=announcements)

@app.route('/profile')
def profile():
    """User profile page - protected"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, email, first_name, last_name, user_type, phone, address, profile_picture, created_at FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        # Add profile picture URL to user data
        if user:
            user = dict(user)
            user['profile_picture_url'] = get_profile_picture_url(user.get('profile_picture'))
        
    except Exception as e:
        print(f"Error: {e}")
        user = None
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Update user profile - protected"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get form data with validation
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        
        # Validate required fields
        if not first_name or not last_name or not email:
            flash('First name, last name, and email are required!', 'danger')
            return redirect(url_for('profile'))
        
        # Validate email format
        if '@' not in email or '.' not in email:
            flash('Please enter a valid email address!', 'danger')
            return redirect(url_for('profile'))
        
        # Handle profile picture upload and clearing
        profile_picture = None
        old_profile_picture = None
        clear_profile_picture = request.form.get('clear_profile_picture') == '1'
        
        # Get old profile picture for cleanup
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT profile_picture FROM users WHERE id = ?", (session['user_id'],))
            old_user = cursor.fetchone()
            if old_user and old_user['profile_picture']:
                old_profile_picture = old_user['profile_picture']
        except Exception as e:
            print(f"Error getting old profile picture: {e}")
        finally:
            if 'conn' in locals():
                conn.close()
        
        # Handle profile picture clearing
        if clear_profile_picture and old_profile_picture:
            try:
                # Remove old profile picture files
                upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics')
                static_uploads_dir = os.path.join('static', 'uploads', 'profile_pics')
                
                old_file_path = os.path.join(upload_dir, old_profile_picture)
                old_static_path = os.path.join(static_uploads_dir, old_profile_picture)
                
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
                if os.path.exists(old_static_path):
                    os.remove(old_static_path)
                
                profile_picture = None  # Clear profile picture
                print(f"Profile picture cleared: {old_profile_picture}")
                
            except Exception as clear_error:
                print(f"Error clearing profile picture: {clear_error}")
                flash('Error clearing profile picture. Please try again.', 'danger')
                return redirect(url_for('profile'))
        
        # Handle new profile picture upload (only if not clearing)
        elif 'profile_picture' in request.files and not clear_profile_picture:
            file = request.files['profile_picture']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    try:
                        # Create uploads directory if it doesn't exist
                        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics')
                        os.makedirs(upload_dir, exist_ok=True)
                        
                        # Generate unique filename
                        filename = secure_filename(file.filename)
                        unique_filename = f"{session['user_id']}_{int(get_current_time().timestamp())}_{filename}"
                        file_path = os.path.join(upload_dir, unique_filename)
                        
                        # Save file
                        file.save(file_path)
                        
                        # Process image for better quality and resolution
                        processed_filename = process_profile_picture(file_path, session['user_id'])
                        profile_picture = processed_filename
                        
                        # Copy to static directory for web access
                        static_uploads_dir = os.path.join('static', 'uploads', 'profile_pics')
                        os.makedirs(static_uploads_dir, exist_ok=True)
                        static_file_path = os.path.join(static_uploads_dir, processed_filename)
                        
                        source_path = os.path.join(upload_dir, processed_filename)
                        if os.path.exists(source_path):
                            import shutil
                            shutil.copy2(source_path, static_file_path)
                        
                        # Clean up old profile picture
                        if old_profile_picture:
                            old_file_path = os.path.join(upload_dir, old_profile_picture)
                            old_static_path = os.path.join(static_uploads_dir, old_profile_picture)
                            if os.path.exists(old_file_path):
                                os.remove(old_file_path)
                            if os.path.exists(old_static_path):
                                os.remove(old_static_path)
                        
                        print(f"Profile picture processed and saved: {processed_filename}")
                        
                    except Exception as save_error:
                        print(f"Error saving profile picture: {save_error}")
                        flash('Error saving profile picture. Please try again.', 'danger')
                        return redirect(url_for('profile'))
                else:
                    flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'danger')
                    return redirect(url_for('profile'))
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if email is already used by another user
            cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, session['user_id']))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Email address is already used by another user!', 'danger')
                return redirect(url_for('profile'))
            
            # Update profile with optional profile picture
            if clear_profile_picture:
                cursor.execute("""
                    UPDATE users 
                    SET first_name = ?, last_name = ?, email = ?, phone = ?, address = ?, profile_picture = ?, updated_at = ?
                    WHERE id = ?
                """, (first_name, last_name, email, phone, address, None, get_current_time(), session['user_id']))
                print(f"Cleared profile picture for user {session['user_id']}")
            elif profile_picture:
                cursor.execute("""
                    UPDATE users 
                    SET first_name = ?, last_name = ?, email = ?, phone = ?, address = ?, profile_picture = ?, updated_at = ?
                    WHERE id = ?
                """, (first_name, last_name, email, phone, address, profile_picture, get_current_time(), session['user_id']))
                print(f"Updated profile with new picture for user {session['user_id']}")
            else:
                cursor.execute("""
                    UPDATE users 
                    SET first_name = ?, last_name = ?, email = ?, phone = ?, address = ?, updated_at = ?
                    WHERE id = ?
                """, (first_name, last_name, email, phone, address, get_current_time(), session['user_id']))
                print(f"Updated profile without picture for user {session['user_id']}")
            
            conn.commit()
            
            # Update session data
            session['first_name'] = first_name
            session['last_name'] = last_name
            session['email'] = email
            
            if clear_profile_picture:
                session.pop('profile_picture', None)  # Remove from session
                flash('Profile picture removed successfully!', 'success')
            elif profile_picture:
                session['profile_picture'] = profile_picture
                flash('Profile updated successfully!', 'success')
            else:
                flash('Profile updated successfully!', 'success')
            
        except sqlite3.Error as db_error:
            print(f"Database error: {db_error}")
            flash('Database error occurred. Please try again.', 'danger')
        except Exception as e:
            print(f"Error updating profile: {e}")
            flash('Failed to update profile!', 'danger')
        finally:
            if 'conn' in locals():
                conn.close()
    
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
def change_password():
    """Change user password - protected"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required!', 'danger')
            return redirect(url_for('profile'))
        
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger')
            return redirect(url_for('profile'))
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters!', 'danger')
            return redirect(url_for('profile'))
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get current password
            cursor.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            
            if not user:
                flash('User not found!', 'danger')
                return redirect(url_for('profile'))
            
            if check_password_hash(user['password'], current_password):
                # Update password
                hashed_password = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password = ?, updated_at = ? WHERE id = ?", 
                             (hashed_password, get_current_time(), session['user_id']))
                conn.commit()
                print(f"Password updated successfully for user {session['user_id']}")
                flash('Password changed successfully!', 'success')
            else:
                flash('Current password is incorrect!', 'danger')
                
        except sqlite3.Error as db_error:
            print(f"Database error during password change: {db_error}")
            flash('Database error occurred. Please try again.', 'danger')
        except Exception as e:
            print(f"Error changing password: {e}")
            flash('Failed to change password!', 'danger')
        finally:
            if 'conn' in locals():
                conn.close()
    
    return redirect(url_for('profile'))

def save_concern_image(file, concern_id):
    """Save concern image and return the file path"""
    if not file or file.filename == '':
        return None
        
    try:
        # Create uploads directory if it doesn't exist
        upload_folder = os.path.join(app.root_path, 'static', 'uploads', 'concerns')
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate a secure filename with timestamp to prevent overwrites
        timestamp = int(time.time())
        filename = f"{concern_id}_{timestamp}_{secure_filename(file.filename)}"
        file_path = os.path.join(upload_folder, filename)
        
        # Save the file
        file.save(file_path)
        
        # Process the image (resize, optimize, etc.)
        try:
            img = Image.open(file_path)
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'P':
                    img = img.convert('RGBA')
                if img.mode == 'RGBA':
                    background.paste(img, mask=img.split()[-1])
                    img = background
                else:
                    img = img.convert('RGB')
            
            # Resize if needed (max 1200px width/height)
            max_size = (1200, 1200)
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # Save with optimized quality
            img.save(file_path, 'JPEG', quality=85, optimize=True)
            
            # Return relative path without 'static/' prefix for consistency
            return f"uploads/concerns/{filename}"
            
        except Exception as e:
            print(f"Error processing image: {e}")
            # If image processing fails, still return the original file
            return f"uploads/concerns/{filename}"
            
    except Exception as e:
        print(f"Error saving file: {e}")
        app.logger.error(f"Failed to save concern image: {str(e)}")
        return None

@app.route('/submit_concern', methods=['POST'])
def submit_concern():
    """Submit a new concern with optional image - protected"""
    if 'user_id' not in session:
        flash('Please login to submit a concern.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location', '')
        image = request.files.get('image')
        
        if not title or not description:
            flash('Title and description are required!', 'danger')
            return redirect(url_for('report_concern'))
        
        # Validate file if provided
        if image and image.filename != '':
            if not allowed_file(image.filename):
                flash('Invalid file type. Only JPG, PNG, and GIF are allowed.', 'danger')
                return redirect(url_for('report_concern'))
            
            # Check file size (5MB max)
            if request.content_length > 5 * 1024 * 1024:  # 5MB
                flash('File size exceeds 5MB limit.', 'danger')
                return redirect(url_for('report_concern'))
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # First insert the concern to get an ID
            current_time = get_current_time()
            print(f"DEBUG: Inserting new concern - User: {session['user_id']}, Title: {title}")
            
            cursor.execute("""
                INSERT INTO concerns (user_id, title, description, location, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """, (session['user_id'], title, description, location, current_time, current_time))
            
            concern_id = cursor.lastrowid
            conn.commit()  # Ensure the insert is committed
            print(f"DEBUG: New concern created with ID: {concern_id}")
            
            # Verify the concern was inserted
            cursor.execute("SELECT * FROM concerns WHERE id = ?", (concern_id,))
            inserted = cursor.fetchone()
            print(f"DEBUG: Verifying concern - Found: {bool(inserted)}")
            if inserted:
                print(f"DEBUG: Concern details: {dict(inserted)}")
            image_path = None
            
            # Handle image upload if provided
            if image and image.filename != '':
                try:
                    image_path = save_concern_image(image, concern_id)
                    if image_path:
                        # Update the concern with the image path
                        cursor.execute("""
                            UPDATE concerns 
                            SET image_path = ?, updated_at = ?
                            WHERE id = ?
                        """, (image_path, get_current_time(), concern_id))
                        conn.commit()
                    else:
                        # If image processing failed but the concern should still be saved
                        flash('Your concern was submitted, but there was an issue processing the image.', 'warning')
                except Exception as e:
                    app.logger.error(f"Error processing concern image: {str(e)}")
                    # Continue without failing the entire request if image processing fails
                    flash('Your concern was submitted, but there was an issue processing the image.', 'warning')
            
            flash('Your concern has been submitted successfully!', 'success')
            
            # Log the activity
            log_user_activity(
                user_id=session['user_id'],
                action='submit_concern',
                details=f'Submitted concern: {title}' + (f' with image: {image_path}' if image_path else ''),
                ip_address=request.remote_addr
            )
            
            return redirect(url_for('report_concern'))
            
        except sqlite3.Error as e:
            conn.rollback()
            print(f"Database error: {e}")
            flash('An error occurred while submitting your concern. Please try again.', 'danger')
            return redirect(url_for('report_concern'))
            
        except Exception as e:
            if 'conn' in locals():
                conn.rollback()
            print(f"Error in submit_concern: {e}")
            flash('An error occurred while processing your request. Please try again.', 'danger')
            return redirect(url_for('report_concern'))
            
        finally:
            if 'conn' in locals():
                conn.close()
    
    return redirect(url_for('report_concern'))

@app.route('/my_concerns')
def my_concerns():
    """View user's concerns - protected"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user's concerns with user details
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name
            FROM concerns c
            JOIN users u ON c.user_id = u.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        """, (session['user_id'],))
        
        # Convert string dates to datetime objects
        concerns = []
        for row in cursor.fetchall():
            concern = dict(row)
            # Convert string dates to datetime objects
            concern['created_at'] = datetime.strptime(concern['created_at'], '%Y-%m-%d %H:%M:%S')
            concern['updated_at'] = datetime.strptime(concern['updated_at'], '%Y-%m-%d %H:%M:%S')
            concerns.append(concern)
        
        return render_template('my_concerns.html', 
                            title='My Concerns',
                            concerns=concerns,
                            format_datetime=format_datetime)
        
    except sqlite3.Error as e:
        print(f"Database error in my_concerns: {e}")
        flash('An error occurred while fetching your concerns.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Error in my_concerns: {e}")
        flash('An error occurred while processing your request.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/all_concerns')
def all_concerns():
    """View all concerns - admin only"""
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all concerns with user details
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name, u.email
            FROM concerns c
            JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC
        """)
        
        # Convert string dates to datetime objects and process image paths
        concerns = []
        for row in cursor.fetchall():
            concern = dict(row)
            
            # Process image path
            if concern.get('image_path'):
                concern['image_path'] = concern['image_path'].replace('\\', '/')
                if concern['image_path'].startswith('static/'):
                    concern['image_path'] = concern['image_path'][7:]  # Remove 'static/' prefix
            
            # Helper function to parse datetime strings
            def parse_datetime(dt_str):
                if not dt_str:
                    return None
                # Remove timezone part if present
                dt_str = dt_str.split('+')[0].strip()
                # Try different formats
                for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']:
                    try:
                        return datetime.strptime(dt_str, fmt)
                    except ValueError:
                        continue
                return None
                
            # Convert string dates to datetime objects
            concern['created_at'] = parse_datetime(concern['created_at'])
            concern['updated_at'] = parse_datetime(concern['updated_at'])
            concerns.append(concern)
        
        return render_template('all_concerns.html', 
                            title='All Concerns',
                            concerns=concerns,
                            format_datetime=format_datetime)
        
    except sqlite3.Error as e:
        print(f"Database error in all_concerns: {e}")
        flash('An error occurred while fetching concerns.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Unexpected error in all_concerns: {e}")
        flash('An unexpected error occurred.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/update_concern_status/<int:concern_id>', methods=['POST'])
def update_concern_status(concern_id):
    """Update concern status - admin only"""
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    status = request.form.get('status')
    if not status or status not in ['pending', 'in_progress', 'resolved']:
        flash('Invalid status provided.', 'danger')
        return redirect(url_for('all_concerns'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update the concern status
        cursor.execute("""
            UPDATE concerns 
            SET status = ?, 
                updated_at = ?
            WHERE id = ?
        """, (status, get_current_time(), concern_id))
        
        # Get concern details for logging
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name 
            FROM concerns c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ?
        """, (concern_id,))
        
        concern = cursor.fetchone()
        
        if concern:
            # Log the activity
            log_user_activity(
                user_id=session['user_id'],
                action='update_concern_status',
                details=f"Updated concern #{concern_id} status to {status}",
                target_user_id=concern['user_id'],
                ip_address=request.remote_addr
            )
        
        conn.commit()
        flash('Concern status updated successfully!', 'success')
        
    except sqlite3.Error as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"Database error in update_concern_status: {e}")
        flash('An error occurred while updating the concern status.', 'danger')
    
    finally:
        if 'conn' in locals():
            conn.close()
    
    return redirect(url_for('all_concerns'))

@app.route('/create_event', methods=['POST'])
def create_event():
    """Create new event - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    title = request.form.get('title')
    description = request.form.get('description')
    event_date = request.form.get('event_date')
    event_time = request.form.get('event_time')
    location = request.form.get('location')
    
    if not title or not event_date:
        flash('Title and date are required!', 'danger')
        return redirect(url_for('events'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            INSERT INTO events (title, description, event_date, event_time, location, is_published)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (title, description, event_date, event_time, location),
        )
        conn.commit()
        flash('Event created successfully!', 'success')
    except Exception as e:
        print(f"Error creating event: {e}")
        flash('Failed to create event!', 'danger')
    finally:
        if 'conn' in locals():
            conn.close()
    
    return redirect(url_for('events'))

@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    """Delete event - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM events WHERE id = ?", (event_id,))
        conn.commit()
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting event: {e}")
        flash('Failed to delete event!', 'danger')
    finally:
        if 'conn' in locals():
            conn.close()

    return redirect(url_for('events'))

@app.route('/get_events')
def get_events():
    """Get events for calendar - protected"""
    if 'user_id' not in session:
        return jsonify([])

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, title, event_date, event_time, location 
            FROM events 
            WHERE is_published = 1 AND event_date IS NOT NULL
            """
        )
        events = cursor.fetchall()

        events_list = []
        for event in events:
            events_list.append(
                {
                    'id': event['id'],
                    'title': event['title'],
                    'start': event['event_date'],
                    'time': event['event_time'],
                    'location': event['location'],
                    'url': url_for('events'),
                }
            )
    except Exception as e:
        print(f"Error: {e}")
        events_list = []
    finally:
        if 'conn' in locals():
            conn.close()

    return jsonify(events_list)

@app.route('/manage_users')
def manage_users():
    """Legacy route - redirect to main user management dashboard."""
    return redirect(url_for('user_management'))

@app.route('/create_user', methods=['POST'])
@admin_required
def create_user():
    """Create a new user account - admin only"""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    address = request.form.get('address', '').strip()
    phone = request.form.get('phone', '').strip()
    user_type = request.form.get('user_type', 'resident')
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not username or not email or not first_name or not last_name:
        return user_action_response(
            False,
            'First name, last name, username, and email are required.',
            400,
        )

    if password or confirm_password:
        if password != confirm_password:
            return user_action_response(False, 'Passwords do not match.', 400)
        if len(password) < 6:
            return user_action_response(
                False, 'Password must be at least 6 characters.', 400
            )
        hashed_password = generate_password_hash(password)
    else:
        # Default password if none provided (admin can communicate this to user)
        hashed_password = generate_password_hash('padolina123')

    if user_type not in ('admin', 'resident'):
        user_type = 'resident'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT 1 FROM users WHERE username = ? OR email = ?",
            (username, email),
        )
        if cursor.fetchone():
            return user_action_response(
                False, 'Username or email already exists.', 400
            )

        cursor.execute(
            """
            INSERT INTO users (
                username,
                email,
                password,
                first_name,
                last_name,
                user_type,
                address,
                phone,
                is_active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                username,
                email,
                hashed_password,
                first_name,
                last_name,
                user_type,
                address,
                phone,
            ),
        )
        conn.commit()

        # Audit log
        try:
            cursor.execute(
                """
                INSERT INTO user_activity_log (admin_id, target_user_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    session.get('user_id'),
                    cursor.lastrowid,
                    'create_user',
                    f"Created user username={username}, email={email}, role={user_type}",
                ),
            )
            conn.commit()
        except Exception as log_err:
            print(f"Error logging create_user activity: {log_err}")

        return user_action_response(True, 'User created successfully.')
    except Exception as e:
        print(f"Error creating user: {e}")
        return user_action_response(False, 'Failed to create user.', 500)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    """Edit an existing user account - admin only"""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    address = request.form.get('address', '').strip()
    phone = request.form.get('phone', '').strip()
    user_type = request.form.get('user_type', 'resident')
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not username or not email or not first_name or not last_name:
        return user_action_response(
            False,
            'First name, last name, username, and email are required.',
            400,
        )

    update_password = False
    if password or confirm_password:
        if password != confirm_password:
            return user_action_response(False, 'Passwords do not match.', 400)
        if len(password) < 6:
            return user_action_response(
                False, 'Password must be at least 6 characters.', 400
            )
        update_password = True
        hashed_password = generate_password_hash(password)

    if user_type not in ('admin', 'resident'):
        user_type = 'resident'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT 1 FROM users WHERE (username = ? OR email = ?) AND id != ?",
            (username, email, user_id),
        )
        if cursor.fetchone():
            return user_action_response(
                False,
                'Username or email already exists for another account.',
                400,
            )

        if update_password:
            cursor.execute(
                """
                UPDATE users
                SET username = ?, email = ?, first_name = ?, last_name = ?,
                    address = ?, phone = ?, user_type = ?, password = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    username,
                    email,
                    first_name,
                    last_name,
                    address,
                    phone,
                    user_type,
                    hashed_password,
                    get_current_time(),
                    user_id,
                ),
            )
        else:
            cursor.execute(
                """
                UPDATE users
                SET username = ?, email = ?, first_name = ?, last_name = ?,
                    address = ?, phone = ?, user_type = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    username,
                    email,
                    first_name,
                    last_name,
                    address,
                    phone,
                    user_type,
                    get_current_time(),
                    user_id,
                ),
            )

        conn.commit()
        # Audit log
        try:
            cursor.execute(
                """
                INSERT INTO user_activity_log (admin_id, target_user_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    session.get('user_id'),
                    user_id,
                    'edit_user',
                    f"Updated user username={username}, email={email}, role={user_type}",
                ),
            )
            conn.commit()
        except Exception as log_err:
            print(f"Error logging edit_user activity: {log_err}")

        return user_action_response(True, 'User updated successfully.')
    except Exception as e:
        print(f"Error updating user: {e}")
        return user_action_response(False, 'Failed to update user.', 500)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user account - admin only"""
    if user_id == session.get('user_id'):
        return user_action_response(False, 'You cannot delete your own account.', 400)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

        try:
            cursor.execute(
                """
                INSERT INTO user_activity_log (admin_id, target_user_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    session.get('user_id'),
                    user_id,
                    'delete_user',
                    f"Deleted user id={user_id}",
                ),
            )
            conn.commit()
        except Exception as log_err:
            print(f"Error logging delete_user activity: {log_err}")

        return user_action_response(True, 'User deleted successfully.')
    except Exception as e:
        print(f"Error deleting user: {e}")
        return user_action_response(False, 'Failed to delete user.', 500)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/update_user_status/<int:user_id>', methods=['POST'])
@admin_required
def update_user_status(user_id):
    """Update user status (active/inactive) - admin only"""
    is_active_value = request.form.get('is_active')
    is_active = 1 if parse_bool(is_active_value, default=True) else 0

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users
            SET is_active = ?, updated_at = ?
            WHERE id = ?
            """,
            (is_active, get_current_time(), user_id),
        )
        conn.commit()

        try:
            cursor.execute(
                """
                INSERT INTO user_activity_log (admin_id, target_user_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    session.get('user_id'),
                    user_id,
                    'update_status',
                    f"Set is_active={is_active} for user id={user_id}",
                ),
            )
            conn.commit()
        except Exception as log_err:
            print(f"Error logging update_user_status activity: {log_err}")

        return user_action_response(True, 'User status updated successfully.')
    except Exception as e:
        print(f"Error updating user status: {e}")
        return user_action_response(False, 'Failed to update user status.', 500)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/update_user_role/<int:user_id>', methods=['POST'])
@admin_required
def update_user_role(user_id):
    """Update user role (admin/resident) - admin only"""
    user_type = request.form.get('user_type')
    if user_type not in ('admin', 'resident'):
        return user_action_response(False, 'Invalid user role.', 400)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users
            SET user_type = ?, updated_at = ?
            WHERE id = ?
            """,
            (user_type, get_current_time(), user_id),
        )
        conn.commit()

        try:
            cursor.execute(
                """
                INSERT INTO user_activity_log (admin_id, target_user_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    session.get('user_id'),
                    user_id,
                    'update_role',
                    f"Changed role to {user_type} for user id={user_id}",
                ),
            )
            conn.commit()
        except Exception as log_err:
            print(f"Error logging update_user_role activity: {log_err}")

        return user_action_response(True, 'User role updated successfully.')
    except Exception as e:
        print(f"Error updating user role: {e}")
        return user_action_response(False, 'Failed to update user role.', 500)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/get_reports_data')
def get_reports_data():
    """Get data for admin reports - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get total counts
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM concerns")
        total_concerns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM announcements")
        total_announcements = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]

        # Get user distribution
        cursor.execute("SELECT user_type, COUNT(*) FROM users GROUP BY user_type")
        user_distribution_raw = cursor.fetchall()
        user_distribution = {'labels': [], 'data': []}
        for user_type, count in user_distribution_raw:
            user_distribution['labels'].append(user_type.title())
            user_distribution['data'].append(count)

        # Get recent concerns with status
        cursor.execute("""
            SELECT c.id, c.title, c.status, c.created_at, u.username
            FROM concerns c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC
            LIMIT 10
        """)
        recent_concerns = []
        for row in cursor.fetchall():
            recent_concerns.append({
                'id': row[0],
                'title': row[1],
                'status': row[2],
                'created_at': row[3],
                'username': row[4] or 'Unknown'
            })

        # Get recent announcements with author names and content
        cursor.execute("""
            SELECT a.id, a.title, a.content, a.created_at, u.username
            FROM announcements a
            LEFT JOIN users u ON a.author_id = u.id
            WHERE a.is_published = 1
            ORDER BY a.created_at DESC
            LIMIT 5
        """)
        recent_announcements = []
        for row in cursor.fetchall():
            recent_announcements.append({
                'id': row[0],
                'title': row[1],
                'content': row[2],  # Added content
                'created_at': row[3],
                'author_name': row[4] or 'System'
            })

        # Get daily activity for the last 7 days
        cursor.execute("""
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count
            FROM user_activity_log
            WHERE created_at >= date('now', '-7 days')
            GROUP BY DATE(created_at)
            ORDER BY date
        """)
        daily_activity_raw = cursor.fetchall()
        
        # Fill missing dates with 0 activity
        daily_activity = {'labels': [], 'data': []}
        from datetime import datetime, timedelta
        
        for i in range(7):
            date = get_current_time() - timedelta(days=6-i)
            date_str = date.strftime('%Y-%m-%d')
            count = 0
            
            for row in daily_activity_raw:
                if row[0] == date_str:
                    count = row[1]
                    break
            
            daily_activity['labels'].append(date.strftime('%m/%d'))
            daily_activity['data'].append(count)

        # Get concerns by status
        cursor.execute("""
            SELECT status, COUNT(*) as count 
            FROM concerns 
            GROUP BY status
        """)
        concerns_by_status_raw = cursor.fetchall()
        concerns_by_status = {}
        for status, count in concerns_by_status_raw:
            concerns_by_status[status] = count

        # Get monthly user registrations
        cursor.execute("""
            SELECT 
                strftime('%Y-%m', created_at) as month,
                COUNT(*) as count
            FROM users
            WHERE created_at >= date('now', '-12 months')
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY month
        """)
        monthly_registrations_raw = cursor.fetchall()
        monthly_registrations = {'labels': [], 'data': []}
        for month, count in monthly_registrations_raw:
            monthly_registrations['labels'].append(month)
            monthly_registrations['data'].append(count)

        # Get top active users
        cursor.execute("""
            SELECT 
                u.username,
                COUNT(al.id) as activity_count
            FROM users u
            LEFT JOIN user_activity_log al ON u.id = al.admin_id
            WHERE al.created_at >= date('now', '-30 days')
            GROUP BY u.id, u.username
            ORDER BY activity_count DESC
            LIMIT 5
        """)
        top_users_raw = cursor.fetchall()
        top_users = []
        for username, count in top_users_raw:
            top_users.append({
                'username': username,
                'activity_count': count
            })

        return jsonify({
            'total_users': total_users,
            'total_concerns': total_concerns,
            'total_announcements': total_announcements,
            'total_events': total_events,
            'user_distribution': user_distribution,
            'recent_concerns': recent_concerns,
            'recent_announcements': recent_announcements,  # Now includes content
            'daily_activity': daily_activity,
            'concerns_by_status': concerns_by_status,
            'monthly_registrations': monthly_registrations,
            'top_users': top_users
        })

    except Exception as e:
        print(f"Error getting reports data: {e}")
        return jsonify({'error': 'Failed to get reports data'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/get_activity_log')
def get_activity_log():
    """Get paginated activity log for reports - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        page = int(request.args.get('page', 1))
        filter_type = request.args.get('filter', 'all')
        items_per_page = 20
        offset = (page - 1) * items_per_page

        conn = get_db_connection()
        cursor = conn.cursor()

        # Build WHERE clause based on filter
        where_clause = ""
        params = []
        
        if filter_type != 'all':
            if filter_type == 'login':
                where_clause = "WHERE action IN ('login', 'logout')"
            elif filter_type == 'concern':
                where_clause = "WHERE action LIKE '%concern%'"
            elif filter_type == 'announcement':
                where_clause = "WHERE action LIKE '%announcement%'"

        # Get total count for pagination
        count_query = f"SELECT COUNT(*) FROM user_activity_log {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        total_pages = (total_count + items_per_page - 1) // items_per_page

        # Get activities with user info
        query = f"""
            SELECT 
                al.id,
                al.admin_id,
                al.target_user_id,
                al.action,
                al.details,
                al.created_at,
                u.username,
                u.first_name,
                u.last_name
            FROM user_activity_log al
            LEFT JOIN users u ON al.admin_id = u.id
            {where_clause}
            ORDER BY al.created_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([items_per_page, offset])
        
        cursor.execute(query, params)
        activities = []
        for row in cursor.fetchall():
            activities.append({
                'id': row[0],
                'admin_id': row[1],
                'target_user_id': row[2],
                'action': row[3],
                'details': row[4],
                'created_at': row[5],
                'user_name': f"{row[7] or ''} {row[8] or ''} ({row[6] or 'Unknown'})".strip() or 'Unknown'
            })

        return jsonify({
            'activities': activities,
            'current_page': page,
            'total_pages': total_pages,
            'total_count': total_count,
            'items_per_page': items_per_page
        })

    except Exception as e:
        print(f"Error getting activity log: {e}")
        return jsonify({'error': 'Failed to get activity log'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/get_login_logs')
def get_login_logs():
    """Get paginated login logs for reports - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        page = int(request.args.get('page', 1))
        filter_type = request.args.get('filter', 'all')
        items_per_page = 20
        offset = (page - 1) * items_per_page

        conn = get_db_connection()
        cursor = conn.cursor()

        # Build WHERE clause based on filter
        where_clause = ""
        params = []
        
        if filter_type != 'all':
            if filter_type == 'success':
                where_clause = "WHERE login_status = 'success'"
            elif filter_type == 'failed':
                where_clause = "WHERE login_status = 'failed'"
            elif filter_type == 'admin':
                where_clause = "WHERE user_type = 'admin'"

        # Get total count
        count_query = f"SELECT COUNT(*) FROM login_logs {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Get paginated login logs
        query = f"""
            SELECT 
                ll.id,
                ll.username,
                ll.user_type,
                ll.ip_address,
                ll.user_agent,
                ll.login_time,
                ll.login_status,
                CASE 
                    WHEN ll.user_id = 0 THEN 'Unknown User'
                    ELSE u.first_name || ' ' || u.last_name 
                END as full_name
            FROM login_logs ll
            LEFT JOIN users u ON ll.user_id = u.id
            {where_clause}
            ORDER BY ll.login_time DESC
            LIMIT ? OFFSET ?
        """
        params.extend([items_per_page, offset])
        cursor.execute(query, params)
        
        login_logs = []
        for row in cursor.fetchall():
            login_logs.append({
                'id': row['id'],
                'username': row['username'],
                'user_type': row['user_type'],
                'ip_address': row['ip_address'],
                'user_agent': row['user_agent'][:100] + '...' if len(row['user_agent']) > 100 else row['user_agent'],
                'login_time': row['login_time'],
                'login_status': row['login_status'],
                'full_name': row['full_name']
            })

        total_pages = (total_count + items_per_page - 1) // items_per_page

        return jsonify({
            'login_logs': login_logs,
            'current_page': page,
            'total_pages': total_pages,
            'total_count': total_count,
            'items_per_page': items_per_page
        })

    except Exception as e:
        print(f"Error getting login logs: {e}")
        return jsonify({'error': 'Failed to get login logs'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/clear_activity_log', methods=['POST'])
def clear_activity_log():
    """Clear activity log - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete all activity log entries
        cursor.execute("DELETE FROM user_activity_log")
        conn.commit()
        
        # Log the clearing action
        log_user_activity(
            session['user_id'],
            'activity_log_cleared',
            'Activity log cleared by admin',
            request.remote_addr
        )
        
        return jsonify({'success': True, 'message': 'Activity log cleared successfully'})

    except Exception as e:
        print(f"Error clearing activity log: {e}")
        return jsonify({'success': False, 'error': 'Failed to clear activity log'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/clear_login_log', methods=['POST'])
def clear_login_log():
    """Clear login log - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete all login log entries
        cursor.execute("DELETE FROM login_logs")
        conn.commit()
        
        # Log the clearing action
        log_user_activity(
            session['user_id'],
            'login_log_cleared',
            'Login log cleared by admin',
            request.remote_addr
        )
        
        return jsonify({'success': True, 'message': 'Login log cleared successfully'})

    except Exception as e:
        print(f"Error clearing login log: {e}")
        return jsonify({'success': False, 'error': 'Failed to clear login log'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/export_reports')
def export_reports():
    """Export reports in various formats - admin only"""
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        report_type = request.args.get('type', 'all')
        format_type = request.args.get('format', 'pdf')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Build data based on report type
        data = []
        headers = []
        filename = f"report_{report_type}_{get_current_time().strftime('%Y%m%d_%H%M%S')}"

        if report_type == 'users' or report_type == 'all':
            cursor.execute("""
                SELECT id, username, email, first_name, last_name, user_type, phone, address, created_at
                FROM users
                ORDER BY created_at DESC
            """)
            users_data = cursor.fetchall()
            if report_type == 'users':
                headers = ['ID', 'Username', 'Email', 'First Name', 'Last Name', 'User Type', 'Phone', 'Address', 'Created At']
                data = users_data

        elif report_type == 'concerns':
            cursor.execute("""
                SELECT c.id, c.title, c.description, c.location, c.status, c.created_at, u.username
                FROM concerns c
                LEFT JOIN users u ON c.user_id = u.id
                ORDER BY c.created_at DESC
            """)
            concerns_data = cursor.fetchall()
            headers = ['ID', 'Title', 'Description', 'Location', 'Status', 'Created At', 'Reported By']
            data = concerns_data

        elif report_type == 'announcements':
            cursor.execute("""
                SELECT a.id, a.title, a.content, a.is_published, a.is_important, a.created_at, u.username
                FROM announcements a
                LEFT JOIN users u ON a.author_id = u.id
                ORDER BY a.created_at DESC
            """)
            announcements_data = cursor.fetchall()
            headers = ['ID', 'Title', 'Content', 'Published', 'Important', 'Created At', 'Author']
            data = announcements_data

        elif report_type == 'activity':
            cursor.execute("""
                SELECT al.action, al.details, al.ip_address, al.created_at, u.username
                FROM user_activity_log al
                LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.created_at DESC
            """)
            activity_data = cursor.fetchall()
            headers = ['Action', 'Details', 'IP Address', 'Created At', 'User']
            data = activity_data

        # Generate export based on format
        if format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(data)
            
            response = make_response(output.getvalue())
            response.headers['Content-Disposition'] = f'attachment; filename={filename}.csv'
            response.headers['Content-type'] = 'text/csv'
            return response

        elif format_type == 'excel':
            # For Excel export, would need openpyxl or similar
            # For now, return CSV as fallback
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(data)
            
            response = make_response(output.getvalue())
            response.headers['Content-Disposition'] = f'attachment; filename={filename}.csv'
            response.headers['Content-type'] = 'text/csv'
            return response

        elif format_type == 'pdf':
            # For PDF export, would need reportlab or similar
            # For now, return a simple HTML version
            html_content = f"""
            <html>
            <head><title>{filename}</title></head>
            <body>
            <h1>Report: {report_type}</h1>
            <p>Generated: {get_current_time().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <table border="1">
            <tr>
            """
            
            for header in headers:
                html_content += f"<th>{header}</th>"
            html_content += "</tr>"
            
            for row in data:
                html_content += "<tr>"
                for cell in row:
                    html_content += f"<td>{cell or ''}</td>"
                html_content += "</tr>"
            
            html_content += """
            </table>
            </body>
            </html>
            """
            
            response = make_response(html_content)
            response.headers['Content-Disposition'] = f'attachment; filename={filename}.html'
            response.headers['Content-type'] = 'text/html'
            return response

    except Exception as e:
        print(f"Error exporting reports: {e}")
        return jsonify({'error': 'Failed to export reports'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/user_activity_log')
@admin_required
def user_activity_log():
    """View audit trail of admin actions on users - admin only"""
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    per_page = 20

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Count total log entries
        cursor.execute("SELECT COUNT(*) as total FROM user_activity_log")
        total = cursor.fetchone()['total']

        offset = (page - 1) * per_page

        # Join admins and target users for display
        cursor.execute(
            '''
            SELECT l.*, 
                   a.username AS admin_username,
                   a.first_name AS admin_first_name,
                   a.last_name AS admin_last_name,
                   t.username AS target_username,
                   t.first_name AS target_first_name,
                   t.last_name AS target_last_name
            FROM user_activity_log l
            JOIN users a ON l.admin_id = a.id
            LEFT JOIN users t ON l.target_user_id = t.id
            ORDER BY l.created_at DESC
            LIMIT ? OFFSET ?
            ''',
            (per_page, offset),
        )
        logs = cursor.fetchall()

    except Exception as e:
        print(f"Error loading activity log: {e}")
        logs = []
        total = 0
    finally:
        if 'conn' in locals():
            conn.close()

    total_pages = (total + per_page - 1) // per_page if per_page else 1
    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
    }

    return render_template('user_activity_log.html', logs=logs, pagination=pagination)

@app.route('/logout')
def logout():
    """Logout user"""
    # Log logout activity if user was logged in
    if 'user_id' in session:
        log_user_activity(
            session['user_id'],
            'logout',
            f'User {session.get("username", "unknown")} logged out',
            request.remote_addr
        )
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/concern/<int:concern_id>')
def view_concern(concern_id):
    """View a specific concern"""
    if 'user_id' not in session:
        flash('Please login to view this concern.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get the concern with user details
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name, u.email
            FROM concerns c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ? AND (c.user_id = ? OR ? IN (SELECT id FROM users WHERE user_type = 'admin'))
        """, (concern_id, session['user_id'], session['user_id']))
        
        concern = cursor.fetchone()
        if not concern:
            flash('Concern not found or access denied.', 'danger')
            return redirect(url_for('my_concerns'))
            
        # Convert to dict and process dates
        concern = dict(concern)
        concern['created_at'] = datetime.strptime(concern['created_at'], '%Y-%m-%d %H:%M:%S')
        concern['updated_at'] = datetime.strptime(concern['updated_at'], '%Y-%m-%d %H:%M:%S')
        
        # Process image path if it exists
        if concern.get('image_path'):
            # Ensure the path is in the correct format for the template
            concern['image_path'] = concern['image_path'].replace('\\', '/')  # Fix Windows path separators
            if concern['image_path'].startswith('static/'):
                concern['image_path'] = concern['image_path'][7:]  # Remove 'static/' prefix if present
        
        # Check if the current user is the owner or an admin
        is_owner = concern['user_id'] == session['user_id']
        is_admin = session.get('user_type') == 'admin'
        
        return render_template('view_concern.html',
                            title=concern['title'],
                            concern=concern,
                            is_owner=is_owner,
                            is_admin=is_admin,
                            format_datetime=format_datetime)
        
    except Exception as e:
        print(f"Error viewing concern: {e}")
        flash('An error occurred while viewing the concern.', 'danger')
        return redirect(url_for('my_concerns'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/concern/edit/<int:concern_id>', methods=['GET', 'POST'])
def edit_concern(concern_id):
    """Edit a concern"""
    if 'user_id' not in session:
        flash('Please login to edit this concern.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.method == 'GET':
            # Get the concern to edit
            cursor.execute("""
                SELECT * FROM concerns 
                WHERE id = ? AND user_id = ?
            """, (concern_id, session['user_id']))
            
            concern = cursor.fetchone()
            if not concern:
                flash('Concern not found or access denied.', 'danger')
                return redirect(url_for('my_concerns'))
                
            concern = dict(concern)
            return render_template('edit_concern.html', 
                                title='Edit Concern',
                                concern=concern)
        
        # Handle form submission
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location', '')
        image = request.files.get('image')
        remove_image = request.form.get('remove_image') == '1'
        
        if not title or not description:
            flash('Title and description are required!', 'danger')
            return redirect(url_for('edit_concern', concern_id=concern_id))
        
        # Check if the concern exists and belongs to the user
        cursor.execute("""
            SELECT id, image_path FROM concerns 
            WHERE id = ? AND user_id = ?
        """, (concern_id, session['user_id']))
        
        concern = cursor.fetchone()
        if not concern:
            flash('Concern not found or access denied.', 'danger')
            return redirect(url_for('my_concerns'))
            
        concern = dict(concern)
        current_image_path = concern.get('image_path')
        
        # Update the concern
        update_data = {
            'title': title,
            'description': description,
            'location': location,
            'updated_at': get_current_time()
        }
        
        # Handle image removal
        if remove_image and current_image_path:
            try:
                os.remove(os.path.join(app.root_path, current_image_path))
                update_data['image_path'] = None
                current_image_path = None
            except Exception as e:
                print(f"Error removing image: {e}")
        
        # Handle new image upload
        if image and image.filename != '':
            if not allowed_file(image.filename):
                flash('Invalid file type. Only JPG, PNG, and GIF are allowed.', 'danger')
                return redirect(url_for('edit_concern', concern_id=concern_id))
            
            # Remove old image if it exists
            if current_image_path and os.path.exists(os.path.join(app.root_path, current_image_path)):
                try:
                    os.remove(os.path.join(app.root_path, current_image_path))
                except Exception as e:
                    print(f"Error removing old image: {e}")
            
            # Save the new image
            image_path = save_concern_image(image, concern_id)
            if image_path:
                update_data['image_path'] = image_path
        
        # Build and execute the update query
        set_clause = ', '.join([f"{k} = ?" for k in update_data.keys()])
        values = list(update_data.values()) + [concern_id]
        
        cursor.execute(f"""
            UPDATE concerns 
            SET {set_clause}
            WHERE id = ?
        """, values)
        
        conn.commit()
        flash('Concern updated successfully!', 'success')
        
        # Log the activity
        log_user_activity(
            user_id=session['user_id'],
            action='update_concern',
            details=f'Updated concern: {title}',
            ip_address=request.remote_addr
        )
        
        return redirect(url_for('view_concern', concern_id=concern_id))
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"Error updating concern: {e}")
        flash('An error occurred while updating the concern.', 'danger')
        return redirect(url_for('my_concerns'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/concern/delete/<int:concern_id>', methods=['POST'])
def delete_concern(concern_id):
    """Delete a concern"""
    if 'user_id' not in session:
        flash('Please login to delete this concern.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get the concern to delete (only if user is the owner or admin)
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name 
            FROM concerns c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ? AND (c.user_id = ? OR ? IN (SELECT id FROM users WHERE user_type = 'admin'))
        """, (concern_id, session['user_id'], session['user_id']))
        
        concern = cursor.fetchone()
        if not concern:
            flash('Concern not found or access denied.', 'danger')
            return redirect(url_for('my_concerns'))
            
        concern = dict(concern)
        
        # Delete the concern
        cursor.execute("DELETE FROM concerns WHERE id = ?", (concern_id,))
        
        # Delete the associated image if it exists
        if concern.get('image_path'):
            try:
                os.remove(os.path.join(app.root_path, concern['image_path']))
            except Exception as e:
                print(f"Error deleting image: {e}")
        
        conn.commit()
        
        # Log the activity
        log_user_activity(
            user_id=session['user_id'],
            action='delete_concern',
            details=f'Deleted concern: {concern["title"]}',
            ip_address=request.remote_addr
        )
        
        flash('Concern deleted successfully!', 'success')
        
        # Redirect back to report_concern page after deletion
        return redirect(url_for('report_concern'))
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"Error deleting concern: {e}")
        flash('An error occurred while deleting the concern.', 'danger')
        return redirect(url_for('my_concerns'))
    finally:
        if 'conn' in locals():
            conn.close()

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Initialize database when app starts
if __name__ == '__main__':
    with app.app_context():
        init_db()
        print("Database initialized successfully!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)