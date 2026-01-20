import requests
from flask import Blueprint, redirect, request, session, url_for, g, flash
from config import config
import database
import secrets
from functools import wraps

auth_bp = Blueprint('auth', __name__)

def getOidcConfig():
    auth_root = config['oidc']['auth_root_url']
    if not auth_root:
        return None
    try:
        # Check if auth_root ends with slash to avoid double slash or missing slash issues
        # Standard: <issuer>/.well-known/openid-configuration
        url = f"{auth_root.rstrip('/')}/.well-known/openid-configuration"
        resp = requests.get(url)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"Error fetching OIDC config: {e}")
        return None

@auth_bp.route('/login')
def login():
    oidc_cfg = getOidcConfig()
    if not oidc_cfg:
        return "OIDC Configuration Error", 500

    authorization_endpoint = oidc_cfg.get("authorization_endpoint")
    
    # Generate random state
    state = secrets.token_hex(16)
    session['oauth_state'] = state

    client_id = config['oidc']['client_id']
    redirect_uri = url_for('auth.callback', _external=True)
    
    auth_url = (
        f"{authorization_endpoint}?"
        f"response_type=code&"
        f"client_id={client_id}&"
        f"redirect_uri={redirect_uri}&"
        f"scope=openid profile&"
        f"state={state}"
    )
    return redirect(auth_url)

@auth_bp.route('/oidc/callback')
def callback():
    error = request.args.get("error")
    if error:
        return f"Error from OIDC provider: {error}", 400
        
    code = request.args.get("code")
    state = request.args.get("state")
    
    if state != session.get('oauth_state'):
        return "Invalid State", 400
    
    oidc_cfg = getOidcConfig()
    if not oidc_cfg:
        return "OIDC Configuration Error", 500

    token_endpoint = oidc_cfg.get("token_endpoint")
    client_id = config['oidc']['client_id']
    client_secret = config['oidc']['client_secret']
    redirect_uri = url_for('auth.callback', _external=True)

    # Exchange code for token
    token_response = requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    
    if token_response.status_code != 200:
        return f"Failed to get token: {token_response.text}", 400
        
    tokens = token_response.json()
    access_token = tokens.get("access_token")
    
    # Get User Info
    userinfo_endpoint = oidc_cfg.get("userinfo_endpoint")
    userinfo_response = requests.get(
        userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    if userinfo_response.status_code != 200:
        return "Failed to get user info", 400
        
    userinfo = userinfo_response.json()
    sub = userinfo.get("sub")
    preferred_username = userinfo.get("preferred_username", sub) # Fallback to sub if no username

    # Update or Create User in DB
    conn = database.getDb()
    cursor = conn.cursor()
    cursor.execute("SELECT id, preferred_username FROM users WHERE sub = ?", (sub,))
    user = cursor.fetchone()
    
    if user:
        user_id = user['id']
        # Update username if changed
        if user['preferred_username'] != preferred_username:
            cursor.execute("UPDATE users SET preferred_username = ? WHERE id = ?", (preferred_username, user_id))
            conn.commit()
    else:
        cursor.execute("INSERT INTO users (sub, preferred_username) VALUES (?, ?)", (sub, preferred_username))
        conn.commit()
        user_id = cursor.lastrowid
    
    conn.close()
    
    session['user_id'] = user_id
    session['user_name'] = preferred_username
    
    return redirect(url_for('index'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def loginRequired(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function