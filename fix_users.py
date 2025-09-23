import sqlite3
from datetime import datetime

def fix_existing_roles():
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    
    print("=== FIXING EXISTING USER ROLES ===")
    
    # Update NULL roles to 'user'
    c.execute("UPDATE users SET role = 'user' WHERE role IS NULL")
    updated_count = c.rowcount
    
    # Make sure admin user has admin role
    c.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    
    conn.commit()
    
    # Verify changes
    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    
    print(f" Updated {updated_count} users with NULL roles")
    print("\n Current Users:")
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Role: {user[2]}")
    
    conn.close()

if __name__ == "__main__":
    fix_existing_roles()