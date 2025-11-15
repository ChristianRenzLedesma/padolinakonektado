from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'padolina_secret_key_2024'

# Database configuration
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='padolinakonektado'
    )

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM users WHERE username = %s AND is_active = TRUE", (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['first_name'] = user['first_name']
                session['last_name'] = user['last_name']
                session['user_type'] = user['user_type']
                
                flash(f'Welcome back, {user["first_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
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
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        user_type = 'resident'  # Default to resident for registration
        address = request.form['address']
        phone = request.form['phone']
        
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
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                flash('Username or email already exists!', 'danger')
                return render_template('register.html')
            
            # Hash password and create user
            hashed_password = generate_password_hash(password)
            cursor.execute(
                """INSERT INTO users (username, email, password, first_name, last_name, user_type, address, phone) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Redirect to appropriate dashboard based on user type
    if session['user_type'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('resident_dashboard'))

@app.route('/dashboard/admin')
def admin_dashboard():
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get statistics for admin
        cursor.execute("SELECT COUNT(*) as total_users FROM users")
        total_users = cursor.fetchone()['total_users']
        
        cursor.execute("SELECT COUNT(*) as total_concerns FROM concerns")
        total_concerns = cursor.fetchone()['total_concerns']
        
        cursor.execute("SELECT COUNT(*) as pending_concerns FROM concerns WHERE status = 'pending'")
        pending_concerns = cursor.fetchone()['pending_concerns']
        
        cursor.execute("SELECT COUNT(*) as total_announcements FROM announcements")
        total_announcements = cursor.fetchone()['total_announcements']
        
        # Get recent concerns
        cursor.execute("""
            SELECT c.*, u.first_name, u.last_name, u.username 
            FROM concerns c 
            JOIN users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC LIMIT 5
        """)
        recent_concerns = cursor.fetchall()
        
        # Get recent users
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 5")
        recent_users = cursor.fetchall()
        
    except Exception as e:
        print(f"Error: {e}")
        total_users = total_concerns = pending_concerns = total_announcements = 0
        recent_concerns = []
        recent_users = []
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_concerns=total_concerns,
                         pending_concerns=pending_concerns,
                         total_announcements=total_announcements,
                         recent_concerns=recent_concerns,
                         recent_users=recent_users)

@app.route('/dashboard/resident')
def resident_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get recent announcements
        cursor.execute("""
            SELECT a.*, u.first_name, u.last_name 
            FROM announcements a 
            LEFT JOIN users u ON a.author_id = u.id 
            ORDER BY a.created_at DESC LIMIT 5
        """)
        announcements = cursor.fetchall()
        
        # Get upcoming events
        cursor.execute("SELECT * FROM events WHERE event_date >= CURDATE() ORDER BY event_date LIMIT 5")
        events = cursor.fetchall()
        
        # Get user's concerns
        cursor.execute("SELECT COUNT(*) as concern_count FROM concerns WHERE user_id = %s", (session['user_id'],))
        concern_count = cursor.fetchone()['concern_count']
        
        cursor.execute("SELECT * FROM concerns WHERE user_id = %s ORDER BY created_at DESC LIMIT 3", (session['user_id'],))
        my_concerns = cursor.fetchall()
        
    except Exception as e:
        print(f"Error: {e}")
        announcements = []
        events = []
        concern_count = 0
        my_concerns = []
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('resident_dashboard.html', 
                         announcements=announcements, 
                         events=events, 
                         concern_count=concern_count,
                         my_concerns=my_concerns)

@app.route('/announcements')
def announcements():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT a.*, u.first_name, u.last_name 
            FROM announcements a 
            LEFT JOIN users u ON a.author_id = u.id 
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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        
    except Exception as e:
        print(f"Error: {e}")
        user = None
    finally:
        if 'conn' in locals():
            conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)