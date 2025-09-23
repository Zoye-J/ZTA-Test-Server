import sqlite3
from datetime import datetime

def check_database():
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    
    print("=== CURRENT DATABASE STATUS ===")
    
    # Check table structure
    c.execute("PRAGMA table_info(users)")
    columns = c.fetchall()
    print("\n📊 Table Columns:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    
    # Check if users exist
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    
    print(f"\n👥 Current Users: {len(users)}")
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Role: {user[5] if len(user) > 5 else 'NO ROLE COLUMN'}")
    
    conn.close()

if __name__ == "__main__":
    check_database()