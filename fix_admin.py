import sqlite3

def fix_admin_role():
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    
    print("=== FIXING ADMIN USER ROLE ===")
    
    # Check current role
    c.execute("SELECT id, username, role FROM users WHERE username = 'admin'")
    admin_user = c.fetchone()
    print(f"Before fix: ID={admin_user[0]}, Username={admin_user[1]}, Role={admin_user[2]}")
    
    # Fix the role
    c.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    conn.commit()
    
    # Verify fix
    c.execute("SELECT id, username, role FROM users WHERE username = 'admin'")
    admin_user = c.fetchone()
    print(f"After fix: ID={admin_user[0]}, Username={admin_user[1]}, Role={admin_user[2]}")
    
    conn.close()
    print("✅ Admin role fixed!")

if __name__ == "__main__":
    fix_admin_role()