import sqlite3
import mysql.connector
from mysql.connector import Error
import os
import sys
from typing import Union, Tuple, List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

class DatabaseConnection:
    def __init__(self):
        self.connection = None
        self.cursor = None
        self.db_type = None
        self.sqlite_db = 'padolinakonektado.db'
        self.mysql_config = {
            'host': 'localhost',
            'user': 'root',
            'password': '',
            'database': 'padolinakonektado'
        }
        self.schema = self.get_schema()
        self.connect()
        self.initialize_database()

    def connect(self):
        """Try to connect to MySQL first, fallback to SQLite if MySQL is not available"""
        try:
            # Try MySQL connection
            self.connection = mysql.connector.connect(
                host=self.mysql_config['host'],
                user=self.mysql_config['user'],
                password=self.mysql_config['password']
            )
            self.db_type = 'mysql'
            print("Connected to MySQL server")
            
            # Create database if not exists
            cursor = self.connection.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.mysql_config['database']}")
            cursor.close()
            
            # Reconnect to the specific database
            self.connection.database = self.mysql_config['database']
            self.cursor = self.connection.cursor(dictionary=True)
            
        except Error as e:
            print(f"MySQL connection failed: {e}")
            # Fallback to SQLite
            try:
                self.connection = sqlite3.connect(self.sqlite_db)
                self.db_type = 'sqlite'
                # Enable foreign key support for SQLite
                self.connection.execute("PRAGMA foreign_keys = ON")
                self.cursor = self.connection.cursor()
                print("Connected to SQLite database")
            except Error as e:
                print(f"SQLite connection failed: {e}")
                raise Exception("Failed to connect to any database")

    def execute(self, query: str, params: tuple = None, fetch: bool = False, multi: bool = False):
        """Execute a query and return results if fetch is True"""
        try:
            if not self.connection or (self.db_type == 'mysql' and not self.connection.is_connected()):
                self.connect()
            
            # Convert SQLite parameter style if needed
            if self.db_type == 'sqlite' and params is not None and '%s' in query:
                query = query.replace('%s', '?')
            
            if params:
                if multi:
                    self.cursor.executemany(query, params)
                else:
                    self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            
            if fetch:
                if self.db_type == 'mysql':
                    if self.cursor.description:  # If there are results to fetch
                        columns = [col[0] for col in self.cursor.description]
                        results = self.cursor.fetchall()
                        return [dict(zip(columns, row)) if not isinstance(row, dict) else row for row in results]
                    return []
                else:
                    # For SQLite, convert row_factory to dict
                    self.cursor.row_factory = sqlite3.Row
                    return [dict(row) for row in self.cursor.fetchall()]
            else:
                self.connection.commit()
                return self.cursor.lastrowid if hasattr(self.cursor, 'lastrowid') else None
                
        except Exception as e:
            print(f"Database error: {e}")
            if self.connection:
                self.connection.rollback()
            raise e

    def close(self):
        """Close the database connection"""
        if self.connection:
            try:
                if self.db_type == 'mysql' and self.connection.is_connected():
                    self.cursor.close()
                    self.connection.close()
                elif self.db_type == 'sqlite':
                    self.connection.close()
                print("Database connection closed")
            except Exception as e:
                print(f"Error closing connection: {e}")

    def get_schema(self) -> Dict[str, str]:
        """Return the database schema for both MySQL and SQLite"""
        return {
            'users': '''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    first_name VARCHAR(50) NOT NULL,
                    last_name VARCHAR(50) NOT NULL,
                    user_type VARCHAR(20) DEFAULT 'resident',
                    address TEXT,
                    phone VARCHAR(20),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    profile_picture VARCHAR(255) NULL
                )
            ''',
            'contact_messages': '''
                CREATE TABLE IF NOT EXISTS contact_messages (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL,
                    subject VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            'announcements': '''
                CREATE TABLE IF NOT EXISTS announcements (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    title VARCHAR(255) NOT NULL,
                    content TEXT NOT NULL,
                    author_id INTEGER,
                    is_published BOOLEAN DEFAULT TRUE,
                    is_important BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE SET NULL
                )
            ''',
            'events': '''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    event_date DATE,
                    event_time TIME,
                    location TEXT,
                    is_published BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            'concerns': '''
                CREATE TABLE IF NOT EXISTS concerns (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    user_id INTEGER NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    location TEXT,
                    status VARCHAR(20) DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''',
            'password_reset_tokens': '''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    user_id INTEGER NOT NULL,
                    token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''',
            'otp_codes': '''
                CREATE TABLE IF NOT EXISTS otp_codes (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    user_id INTEGER NOT NULL,
                    email VARCHAR(100) NOT NULL,
                    otp_code VARCHAR(10) NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''',
            'user_activity_log': '''
                CREATE TABLE IF NOT EXISTS user_activity_log (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    admin_id INTEGER NOT NULL,
                    target_user_id INTEGER,
                    action VARCHAR(100) NOT NULL,
                    details TEXT,
                    ip_address VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (target_user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            ''',
            'login_logs': '''
                CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    user_id INTEGER NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    user_type VARCHAR(20) NOT NULL,
                    ip_address VARCHAR(50) NOT NULL,
                    user_agent TEXT,
                    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    login_status VARCHAR(20) DEFAULT 'success',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''',
            'system_settings': '''
                CREATE TABLE IF NOT EXISTS system_settings (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    setting_key VARCHAR(100) UNIQUE NOT NULL,
                    setting_value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            '''
        }
    
    def initialize_database(self):
        """Initialize the database with required tables and default data"""
        try:
            # Create all tables
            for table_name, create_sql in self.schema.items():
                # Adjust SQL syntax based on database type
                if self.db_type == 'sqlite':
                    create_sql = create_sql.replace('AUTO_INCREMENT', 'AUTOINCREMENT')
                    create_sql = create_sql.replace('BOOLEAN', 'INTEGER')
                    create_sql = create_sql.replace('TRUE', '1')
                    create_sql = create_sql.replace('FALSE', '0')
                    create_sql = create_sql.replace('ON UPDATE CURRENT_TIMESTAMP', '')
                    
                    # SQLite doesn't support multiple foreign key constraints in one statement
                    if 'FOREIGN KEY' in create_sql and create_sql.count('FOREIGN KEY') > 1:
                        # Split into multiple statements
                        parts = create_sql.split('FOREIGN KEY')
                        base_sql = parts[0].strip().rstrip(',')
                        self.execute(base_sql)
                        
                        # Add each foreign key separately
                        for fk_part in parts[1:]:
                            fk_sql = f"ALTER TABLE {table_name} ADD FOREIGN KEY (" + fk_part.strip().rstrip(',').rstrip(')') + ')'
                            try:
                                self.execute(fk_sql)
                            except Exception as e:
                                print(f"Warning: Could not add foreign key: {e}")
                        continue
                
                self.execute(create_sql)
            
            # Create default admin user if not exists
            admin = self.execute("SELECT * FROM users WHERE username = 'admin'", fetch=True)
            if not admin:
                hashed_password = generate_password_hash('admin123')
                self.execute("""
                    INSERT INTO users (username, email, password, first_name, last_name, user_type, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, ('admin', 'admin@padolinakonektado.ph', hashed_password, 'System', 'Administrator', 'admin', 1), multi=False)
            
            # Insert default system settings if not exists
            settings = self.execute("SELECT * FROM system_settings", fetch=True)
            if not settings:
                default_settings = [
                    ('site_name', 'Padolina Konektado'),
                    ('site_description', 'Community Management System'),
                    ('items_per_page', '10'),
                    ('enable_registration', '1'),
                    ('maintenance_mode', '0')
                ]
                self.execute("""
                    INSERT INTO system_settings (setting_key, setting_value)
                    VALUES (%s, %s)
                """, default_settings, multi=True)
            
            self.connection.commit()
            print("Database initialized successfully")
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            if self.connection:
                self.connection.rollback()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

if __name__ == "__main__":
    # Example usage
    try:
        with DatabaseConnection() as db:
            # Get all users
            users = db.execute("SELECT * FROM users", fetch=True)
            print("Users:", users)
            
            # Get system settings
            settings = db.execute("SELECT * FROM system_settings", fetch=True)
            print("\nSystem Settings:", settings)
            
            # Example of inserting data
            # new_user = {
            #     'username': 'testuser',
            #     'email': 'test@example.com',
            #     'password': 'hashed_password_here',
            #     'first_name': 'Test',
            #     'last_name': 'User',
            #     'user_type': 'resident',
            #     'is_active': 1
            # }
            # 
            # user_id = db.execute(
            #     """
            #     INSERT INTO users (username, email, password, first_name, last_name, user_type, is_active)
            #     VALUES (%s, %s, %s, %s, %s, %s, %s)
            #     """,
            #     (new_user['username'], new_user['email'], new_user['password'], 
            #      new_user['first_name'], new_user['last_name'], 
            #      new_user['user_type'], new_user['is_active'])
            # )
            # print(f"New user created with ID: {user_id}")
            
    except Exception as e:
        print(f"Error: {e}")
        if 'db' in locals():
            db.close()
