# import sqlite3
# import os

# def check_concerns():
#     db_path = 'padolinakonektado.db'
#     print(f"Database path: {os.path.abspath(db_path)}")
#     print(f"Database exists: {os.path.exists(db_path)}")
    
#     try:
#         conn = sqlite3.connect(db_path)
#         conn.row_factory = sqlite3.Row
#         cursor = conn.cursor()
        
#         # Check if concerns table exists
#         cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='concerns'")
#         table_exists = cursor.fetchone()
#         print(f"\nConcerns table exists: {bool(table_exists)}")
        
#         if table_exists:
#             # Get all concerns
#             cursor.execute("SELECT * FROM concerns")
#             concerns = cursor.fetchall()
#             print(f"\nFound {len(concerns)} concerns in the database:")
            
#             for concern in concerns:
#                 concern_dict = dict(concern)
#                 print(f"\nConcern ID: {concern_dict.get('id', 'N/A')}")
#                 print(f"User ID: {concern_dict.get('user_id', 'N/A')}")
#                 print(f"Title: {concern_dict.get('title', 'N/A')}")
#                 print(f"Status: {concern_dict.get('status', 'N/A')}")
#                 print(f"Created At: {concern_dict.get('created_at', 'N/A')}")
#         else:
#             print("\nChecking for any tables in the database:")
#             cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
#             tables = cursor.fetchall()
#             print(f"Found {len(tables)} tables:")
#             for table in tables:
#                 print(f"- {table['name']}")
                
#     except Exception as e:
#         print(f"\nError accessing database: {e}")
#     finally:
#         if 'conn' in locals():
#             conn.close()

# if __name__ == "__main__":
#     check_concerns()
