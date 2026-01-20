from flask import Flask, render_template, g, session, redirect, url_for, abort, request, flash, Response
import os
import sqlite3
import re
import hashlib
import sys
import argparse
import subprocess
import base64
from config import config
import database
from auth import auth_bp, login_required
import git_utils
import markdown
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure paths from config
# Initial load with defaults
data_path = os.path.abspath(config['paths']['data_path'])
template_dir = os.path.join(data_path, 'templates')
static_dir = os.path.join(data_path, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.register_blueprint(auth_bp)

def create_app():
    # Re-evaluate paths in case config changed (e.g. via CLI arg)
    data_path = os.path.abspath(config['paths']['data_path'])
    if not os.path.exists(data_path):
        print(f"Warning: Data path {data_path} does not exist. Creating it.")
        os.makedirs(data_path)

    # Update Flask app paths
    app.template_folder = os.path.join(data_path, 'templates')
    app.static_folder = os.path.join(data_path, 'static')
    
    # Initialize DB
    database.init_db()
    
    # Set Secret Key
    app.secret_key = database.get_or_create_secret_key()
    
    # Ensure repo root exists
    repo_path = config['paths']['repo_path']
    if not os.path.exists(repo_path):
        os.makedirs(repo_path)

    return app

# Initialize the application
create_app()

@app.route('/')
def index():
    conn = database.get_db()
    try:
        repos = conn.execute("""
            SELECT repos.name, users.preferred_username as owner_name 
            FROM repos 
            JOIN users ON repos.owner_id = users.id
        """).fetchall()
    except sqlite3.OperationalError:
        repos = []
    finally:
        conn.close()
        
    return render_template('index.html', repos=repos)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_repo():
    if request.method == 'POST':
        name = request.form.get('name')
        if not name or not re.match(r'^[a-zA-Z0-9._-]+$', name):
            flash("Invalid repository name.")
            return render_template('create.html')
            
        if name.endswith('.git'):
            flash("Repository name should not end with .git")
            return render_template('create.html')
            
        conn = database.get_db()
        try:
            # Check existence
            existing = conn.execute("SELECT 1 FROM repos WHERE name = ?", (name,)).fetchone()
            if existing:
                flash("Repository already exists.")
                return render_template('create.html')
                
            # Create on disk
            try:
                git_utils.init_bare_repo(name)
            except git_utils.GitError as e:
                flash(f"Failed to create repository on disk: {e}")
                return render_template('create.html')
                
            # Insert into DB
            user_id = session['user_id']
            conn.execute("INSERT INTO repos (name, owner_id) VALUES (?, ?)", (name, user_id))
            conn.commit()
            
            flash(f"Repository '{name}' created successfully.")
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f"An error occurred: {e}")
            return render_template('create.html')
        finally:
            conn.close()
            
    return render_template('create.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash("Password cannot be empty.")
            return render_template('settings.html')
            
        salt = os.urandom(16).hex()
        # SHA256(salt + password)
        combined = salt + password
        pw_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        
        conn = database.get_db()
        conn.execute("UPDATE users SET git_password_hash = ?, git_password_salt = ? WHERE id = ?", 
                     (pw_hash, salt, session['user_id']))
        conn.commit()
        conn.close()
        
        flash("Git password updated successfully.")
        return redirect(url_for('index'))
    
    conn = database.get_db()
    repos = conn.execute("SELECT * FROM repos WHERE owner_id = ?", (session['user_id'],)).fetchall()
    conn.close()
        
    return render_template('settings.html', repos=repos)

@app.route('/settings/delete/<repo_name>', methods=['POST'])
@login_required
def delete_repo_route(repo_name):
    conn = database.get_db()
    try:
        repo = conn.execute("SELECT * FROM repos WHERE name = ?", (repo_name,)).fetchone()
        if not repo:
            abort(404)
            
        if repo['owner_id'] != session['user_id']:
            abort(403)
            
        # Delete from disk
        try:
            git_utils.delete_repo(repo_name)
        except Exception as e:
            flash(f"Error deleting repository files: {e}")
            return redirect(url_for('user_settings'))

        # Delete from DB
        conn.execute("DELETE FROM repos WHERE id = ?", (repo['id'],))
        conn.commit()
        
        flash(f"Repository '{repo_name}' deleted successfully.")
    finally:
        conn.close()
        
    return redirect(url_for('user_settings'))

@app.route('/<repo_name>/')
def view_repo(repo_name):
    # Check if repo exists in DB
    conn = database.get_db()
    exists = conn.execute("SELECT 1 FROM repos WHERE name = ?", (repo_name,)).fetchone()
    conn.close()
    if not exists:
         return abort(404)

    if git_utils.is_repo_empty(repo_name):
        clone_url = url_for('git_smart_http', repo_name=repo_name, subpath='', _external=True).rstrip('/')
        default_branch = config['git'].get('default_branch') or 'master'
        return render_template('empty.html', repo_name=repo_name, clone_url=clone_url, default_branch=default_branch)

    try:
        default_branch = git_utils.get_default_branch(repo_name)
    except git_utils.GitError:
        return abort(404)
        
    return redirect(url_for('view_tree', repo_name=repo_name, ref_path=default_branch))

@app.route('/<repo_name>/tree/<path:ref_path>')
def view_tree(repo_name, ref_path):
    conn = database.get_db()
    exists = conn.execute("SELECT 1 FROM repos WHERE name = ?", (repo_name,)).fetchone()
    conn.close()
    if not exists:
         return abort(404)

    try:
        ref, path = git_utils.split_ref_path(repo_name, ref_path)
        files = git_utils.list_tree(repo_name, ref, path)
    except git_utils.GitError:
        return abort(404)

    # Breadcrumbs helper
    path_parts = []
    if path:
        parts = path.split('/')
        current_path = ""
        for part in parts:
            if current_path:
                current_path += "/" + part
            else:
                current_path = part
            path_parts.append({'name': part, 'full_path': current_path})

    # Check for README
    readme_html = None
    for file in files:
        if file['name'].lower() in ['readme.md', 'readme.txt']:
            try:
                content = git_utils.get_blob_content(repo_name, file['object'])
                text_content = content.decode('utf-8', errors='replace')
                if file['name'].lower().endswith('.md'):
                    readme_html = markdown.markdown(text_content)
                else:
                    readme_html = f"<pre>{text_content}</pre>"
            except Exception:
                pass
            break

    return render_template('tree.html', 
                           repo_name=repo_name, 
                           ref=ref, 
                           path=path, 
                           files=files, 
                           path_parts=path_parts,
                           readme_html=readme_html)

@app.route('/<repo_name>/blob/<path:ref_path>')
def view_blob(repo_name, ref_path):
    conn = database.get_db()
    exists = conn.execute("SELECT 1 FROM repos WHERE name = ?", (repo_name,)).fetchone()
    conn.close()
    if not exists:
         return abort(404)

    try:
        ref, path = git_utils.split_ref_path(repo_name, ref_path)
        content_bytes = git_utils.run_git(repo_name, ['cat-file', 'blob', f"{ref}:{path}"], encoding=None)
        
        try:
            content = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            content = "Binary file not shown."
            
    except git_utils.GitError:
        return abort(404)

    path_parts = []
    if path:
        parts = path.split('/')
        current_path = ""
        for part in parts:
            if current_path:
                current_path += "/" + part
            else:
                current_path = part
            path_parts.append({'name': part, 'full_path': current_path})

    return render_template('blob.html',
                           repo_name=repo_name,
                           ref=ref,
                           path=path,
                           content=content,
                           path_parts=path_parts)

@app.route('/<repo_name>/commits/<path:ref>')
def view_commits(repo_name, ref):
    conn = database.get_db()
    exists = conn.execute("SELECT 1 FROM repos WHERE name = ?", (repo_name,)).fetchone()
    conn.close()
    if not exists:
         return abort(404)

    try:
        commits = git_utils.get_commit_log(repo_name, ref)
    except git_utils.GitError:
        return abort(404)
        
    return render_template('commits.html', repo_name=repo_name, ref=ref, commits=commits)


# --- Git Smart HTTP Backend ---

def verify_basic_auth(auth_header):
    if not auth_header:
        return None
    
    try:
        auth_type, encoded = auth_header.split(' ', 1)
        if auth_type.lower() != 'basic':
            return None
        decoded = base64.b64decode(encoded).decode('utf-8')
        username, password = decoded.split(':', 1)
        
        conn = database.get_db()
        user = conn.execute("SELECT * FROM users WHERE preferred_username = ?", (username,)).fetchone()
        conn.close()
        
        if not user or not user['git_password_hash'] or not user['git_password_salt']:
            return None
            
        salt = user['git_password_salt']
        check_hash = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        
        if check_hash == user['git_password_hash']:
            return user
        return None
    except Exception:
        return None

@app.route('/<repo_name>.git/<path:subpath>', methods=['GET', 'POST'])
def git_smart_http(repo_name, subpath):
    # 1. Verify Repo Existence
    conn = database.get_db()
    repo = conn.execute("SELECT * FROM repos WHERE name = ?", (repo_name,)).fetchone()
    conn.close()
    
    if not repo:
        return abort(404)

    # 2. Determine Service and Access Type
    service = request.args.get('service')
    is_write = False
    
    if subpath == 'git-receive-pack' or service == 'git-receive-pack':
        is_write = True
        
    # 3. Authentication & Authorization
    remote_user = None
    
    if is_write:
        auth_header = request.headers.get('Authorization')
        user = verify_basic_auth(auth_header)
        
        if not user:
            return Response(
                'Unauthorized', 401, 
                {'WWW-Authenticate': f'Basic realm="{repo_name}"'} 
            )
            
        if user['id'] != repo['owner_id']:
             return Response('Forbidden', 403)
             
        remote_user = user['preferred_username']

    # 4. Invoke git-http-backend
    backend_path = config['paths']['git_http_backend']
    repo_root = os.path.abspath(config['paths']['repo_path'])
    
    env = os.environ.copy()
    env['GIT_PROJECT_ROOT'] = repo_root
    env['GIT_HTTP_EXPORT_ALL'] = '1'
    env['PATH_INFO'] = request.path # e.g., /repo.git/info/refs
    env['REMOTE_USER'] = remote_user or ''
    env['QUERY_STRING'] = request.query_string.decode('utf-8')
    env['REQUEST_METHOD'] = request.method
    if request.content_length is not None:
        env['CONTENT_LENGTH'] = str(request.content_length)
    env['CONTENT_TYPE'] = request.content_type or ''
    
    # Run subprocess
    proc = subprocess.Popen(
        [backend_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    
    if request.method == 'POST':
        try:
             input_data = request.get_data()
             stdout_data, stderr_data = proc.communicate(input=input_data)
        except Exception as e:
            return Response(f"Internal Error: {e}", 500)
    else:
        stdout_data, stderr_data = proc.communicate()

    if proc.returncode != 0:
        print(f"git-http-backend error: {stderr_data}")
    
    output = stdout_data
    header_end = output.find(b'\r\n\r\n')
    if header_end == -1:
        return Response(output)
        
    headers_raw = output[:header_end].decode('utf-8', errors='replace')
    body = output[header_end+4:]
    
    headers = {}
    for line in headers_raw.split('\r\n'):
        if ':' in line:
            key, val = line.split(':', 1)
            headers[key.strip()] = val.strip()
            
    return Response(body, headers=headers)


# CLI Functions
def import_repo_cli(repo_name, owner_username):
    print(f"Importing repo '{repo_name}' for owner '{owner_username}'...")
    
    # 1. Check disk existence
    try:
        repo_path = git_utils.get_repo_path(repo_name)
    except ValueError:
        print("Invalid repo name format.")
        return
        
    if not os.path.exists(repo_path):
        print(f"Error: Repository directory {repo_path} does not exist.")
        return
        
    conn = database.get_db()
    try:
        # 2. Check DB existence
        row = conn.execute("SELECT 1 FROM repos WHERE name = ?", (repo_name,)).fetchone()
        if row:
            print(f"Error: Repository '{repo_name}' is already in the database.")
            return

        # 3. Check Owner
        user = conn.execute("SELECT id FROM users WHERE preferred_username = ?", (owner_username,)).fetchone()
        if not user:
            print(f"Error: User '{owner_username}' not found. Please login via Web UI first to create the user.")
            return
            
        owner_id = user['id']
        
        # 4. Insert
        conn.execute("INSERT INTO repos (name, owner_id) VALUES (?, ?)", (repo_name, owner_id))
        conn.commit()
        print("Repository imported successfully.")
        
    finally:
        conn.close()

if __name__ == '__main__':
    # CLI Argument Parsing
    parser = argparse.ArgumentParser(
        description='BareGit Management',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--import-repo', help='Import an existing repository by name (folder name without .git)')
    parser.add_argument('--owner', help='Owner username for the imported repo')
    parser.add_argument('--config', default='baregit.ini', help='Path to configuration file')
    
    args = parser.parse_args()

    if args.config:
        from config import reload_config_from_file
        reload_config_from_file(args.config)
        
    # Initialize the application (DB, paths, etc) with potentially new config
    create_app()

    if args.import_repo:
        if not args.owner:
            print("Error: --owner is required.")
            sys.exit(1)
        import_repo_cli(args.import_repo, args.owner)
    else:
        # Run Server
        host = config['server']['host']
        port = int(config['server']['port'])
        debug = config['server'].getboolean('debug')
        app.run(host=host, port=port, debug=debug)
