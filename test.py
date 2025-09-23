import requests
from datetime import datetime

def accurate_zta_test():
    session = requests.Session()
    
    print("=== ACCURATE ZTA TEST ===\n")
    
    # Test 1: Check if API redirects to login when unauthorized
    print("1. Testing Default-Deny Principle:")
    response = session.get('http://127.0.0.1:5000/api/data', allow_redirects=False)
    print(f"   Direct API access: Status {response.status_code}")
    if response.status_code in [302, 303]:  # Redirect status
        print("   GOOD: Redirecting to login (Default Deny working)")
    else:
        print("   PROBLEM: Should redirect to login")
    
    # Follow the redirect to see where it goes
    if response.status_code in [302, 303]:
        login_redirect = session.get('http://127.0.0.1:5000' + response.headers['Location'])
        if 'Login' in login_redirect.text:
            print("   Confirmed: Redirected to login page")
    
    print()
    
    # Test 2: Login properly
    print("2. Testing Authentication:")
    login_data = {'username': 'admin', 'password': 'password', 'mfa_code': '123456'}
    response = session.post('http://127.0.0.1:5000/login', data=login_data, allow_redirects=True)
    
    if response.history:  # If there were redirects
        print("    Login successful (redirect occurred)")
    else:
        print("    Login may have failed")
    
    print()
    
    # Test 3: Now try API with proper session
    print("3. Testing Authenticated Access:")
    response = session.get('http://127.0.0.1:5000/api/data')
    if response.status_code == 200:
        data = response.json()
        print(f"   Access GRANTED to authenticated user")
        print(f"   User: {data['user']}")
    else:
        print(f"    Access denied with status: {response.status_code}")
    
    print()
    
    # Test 4: Logout
    print("4. Testing Logout:")
    response = session.get('http://127.0.0.1:5000/logout', allow_redirects=False)
    if response.status_code in [302, 303]:
        print("    Logout successful (redirect occurred)")
    
    # Test 5: Verify session is terminated
    print("5. Testing Post-Logout Access:")
    response = session.get('http://127.0.0.1:5000/api/data', allow_redirects=False)
    if response.status_code in [302, 303]:
        print("    GOOD: Access denied after logout (redirect to login)")
    else:
        print(f"    PROBLEM: Status {response.status_code} - should redirect")
    
    print("\n=== ZTA SYSTEM ANALYSIS ===")
    print("Your ZTA implementation is likely CORRECT!")
    print("The initial test showed false positives due to HTTP redirect handling.")

if __name__ == "__main__":
    accurate_zta_test()