# Design Document: BareGit

## 1. Overview
BareGit is a lightweight, self-hosted Git web interface built using Python and Flask. It serves two primary functions: a user-friendly web UI for browsing repositories and managing settings, and a Git Smart HTTP backend for standard Git client operations (push/pull). The system is designed to be deployment-friendly, utilizing the Flask development server (as per requirements) and standard library tools (`subprocess`, `sqlite3`, `configparser`) where possible to minimize external dependencies.

**Key constraints:**
*   No heavy frontend frameworks (Bootstrap forbidden).
*   Authentication separation: OIDC for Web, Basic Auth for Git clients.
*   Reliability via standard `git` plumbing commands.

## 2. System Architecture

The system follows a Model-View-Controller (MVC) adaptation appropriate for Flask.

### 2.1. Component Diagram & Data Flow
```
[User Browser] <--(HTTPS/OIDC)--> [Flask Web App] <--(SQL)--> [SQLite DB]
      ^                                  |
      |                                  v
[Git Client]   <--(HTTP Basic)--> [Git Subprocess Wrapper]
                                         |
                                         v
                                  [Filesystem (Repos)]
```

### 2.2. Components
1.  **Request Handler (Flask):** The entry point. It routes URLs to specific view functions. It differentiates between standard Web UI requests (returning HTML) and Git Smart HTTP requests (streaming binary data).
2.  **Authentication Manager:**
    *   **OIDC Handler:** Manages the OAuth2/OIDC state machine (Redirect -> Code -> Token -> User Profile).
    *   **Basic Auth Validator:** Intercepts Git operation requests, parses the `Authorization` header, and verifies credentials against the local database.
3.  **Git Interface Layer:**
    *   **Read-Only (Browser):** A Python abstraction layer that constructs `git` commands (`ls-tree`, `log`, `show`) and executes them via `subprocess.run`. It parses stdout to return Python dictionaries/objects to the views.
    *   **Write/Transport (Smart HTTP):** A generic gateway that utilizes `subprocess.Popen` to create a bidirectional pipe between the incoming Werkzeug request stream and the `git-http-backend` binary.
4.  **Persistence Layer:**
    *   **SQLite3:** Stores relational data (users, repos, config).
    *   **Filesystem:** Stores the actual bare git repositories.

## 3. Data Design

### 3.1. Database Schema (SQLite)

**Table: `users`**
*   *Purpose:* Links the OIDC identity to the local Git identity.
*   `id` (INTEGER PK): Internal reference.
*   `sub` (TEXT UNIQUE NOT NULL): The stable Subject Identifier from the OIDC provider.
*   `preferred_username` (TEXT NOT NULL): The display name/username. Synchronized from OIDC on login.
*   `git_password_hash` (TEXT): The stored hash of the user's Git password.
*   `git_password_salt` (TEXT): A per-user random salt (hex string) used during hashing.

**Table: `repos`**
*   *Purpose:* Registry of known repositories and their ownership.
*   `id` (INTEGER PK): Internal reference.
*   `name` (TEXT UNIQUE NOT NULL): The URL-safe slug for the repository (e.g., `my-project`). Corresponds to directory `repo_path/<name>.git`.
*   `owner_id` (INTEGER FK -> users.id): The user who has write access.

**Table: `system_config`**
*   *Purpose:* Key-value store for runtime persistent data that shouldn't be hardcoded.
*   `key` (TEXT PK): e.g., 'flask_secret_key'.
*   `value` (TEXT NOT NULL): The actual secret.

### 3.2. File System Structure
The application structure separates source code, data, and repositories.

```
/project_root/
    ├── src/                 (Source Code: app.py, git_utils.py, etc.)
    ├── config.ini           (Configuration)
    └── data/                (Configurable `data_path`)
        ├── baregit.db       (SQLite Database)
        ├── templates/       (HTML Templates)
        ├── static/          (CSS/JS Assets)
        └── repos/           (Configurable `repo_path`)
            ├── project-alpha.git/
            └── project-beta.git/
```
*   **Data Path:** Configurable location for DB, templates, and static files (Default: `/var/lib/baregit`).
*   **Repo Path:** Configurable location for bare repositories (Default: `/var/lib/baregit/repos`).

## 4. Configuration
Configuration is loaded once at startup using Python's `configparser`.

**Strategy:**
1.  Define a default configuration dictionary in code.
2.  Read `config.ini` and overwrite defaults.
3.  Validate critical paths (check if `git-http-backend` is executable, `repo_path` exists or can be created).

**Sample Configuration:**
```ini
[server]
host = 127.0.0.1
port = 5000
debug = false

[paths]
# Directory where application data (database, templates, static) lives
data_path = /var/lib/baregit

# Directory where bare repositories are stored
repo_path = /var/lib/baregit/repos

# Path to the git-http-backend executable
git_http_backend = /usr/libexec/git-core/git-http-backend

[git]
# Default branch for new repositories (passed to git init --initial-branch=...)
# Leave empty to use git default
default_branch =

[oidc]
# The root URL of the OIDC provider
auth_root_url = http://localhost:8080/realms/master
client_id = baregit
client_secret = <secret>
```

## 5. Detailed Authentication & Authorization

### 5.1. OIDC Flow (Web UI)
1.  **Discovery:** On startup (or first request), the app queries `{auth_root_url}/.well-known/openid-configuration` to dynamically discover endpoints (`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`).
2.  **Login Request:** User hits `/login`. App generates a random state, saves it to session, and redirects to `authorization_endpoint` with `response_type=code`, `client_id`, `redirect_uri`, and `scope=openid profile`.
3.  **Callback:** OIDC provider redirects to `/oidc/callback?code=...&state=...`.
    *   Verify `state` matches session.
    *   POST `code` to `token_endpoint`. Receive `access_token` and `id_token`.
    *   GET `userinfo_endpoint` with `access_token`. Receive `sub` and `preferred_username`.
4.  **User Provisioning:**
    *   Query DB: `SELECT * FROM users WHERE sub = ?`.
    *   **Case Existing:** Update `preferred_username` if different. Log user in.
    *   **Case New:** `INSERT INTO users (sub, preferred_username) VALUES (...)`. Log user in.
5.  **Session Management:** Flask's secure cookie session stores the `user_id`.

### 5.2. Git Smart HTTP Auth (Basic Auth)
1.  **Request:** Git client sends `GET/POST /<repo>.git/...`.
2.  **Challenge:** If no `Authorization` header, return `401 Unauthorized`.
3.  **Verification:**
    *   Decode Base64 header -> `username:password`.
    *   Look up user by `preferred_username`.
    *   Retrieve `git_password_salt` and `git_password_hash`.
    *   Compute `CheckHash = SHA256(salt + input_password)`.
    *   Compare `CheckHash == git_password_hash`.
4.  **Context Injection:**
    *   If verified, set `REMOTE_USER = username` environment variable for `git-http-backend`.

### 5.3. Authorization Logic
*   **Public Read:** All `GET` requests to repo URLs are allowed for any authenticated or anonymous user (per requirement: "All repos are public").
*   **Owner Write:**
    *   For `git-receive-pack` (Push), check if `repo.owner_id == current_user.id`.
    *   If not owner, return `403 Forbidden`.

## 6. Functional Specifications & Route Logic

### 6.1. Web Interface Routes
*   **Dashboard (`GET /`)**:
    *   Logic: `SELECT * FROM repos`.
    *   Template: Table displaying Repo Name and Owner Name. (No explicit "Actions" column).
    *   Navigation: Username in navbar links to Settings.
*   **Create Repo (`GET/POST /create`)**:
    *   GET: Render form (Repo Name input).
    *   POST:
        1.  Validate name (regex: `^[a-zA-Z0-9-_.]+$`, must not end with `.git`).
        2.  Check DB for uniqueness.
        3.  `os.makedirs(repo_path)`.
        4.  `subprocess.run(['git', 'init', '--bare', ...])`.
        5.  Insert into DB with `owner_id = session['user_id']`.
*   **Repo Settings (`GET/POST /settings`)**:
    *   Allows user to set/change Git HTTP password.
    *   Logic: Generate 16-byte random hex salt. Hash password + salt. Update DB.
*   **Repo View (`GET /<repo_name>`)**:
    *   Logic: Get default branch. Get `README` content. Get root tree.
*   **Tree View (`GET /<repo_name>/tree/<ref>/<path>`)**:
    *   Logic:
        1.  Call `git ls-tree -z --long <ref>:<path>`. Parse null-terminated output to get permissions, type (blob/tree), size, and name.
        2.  Sort directories before files.
        3.  Check for `README.md` or `README.txt` in the current `<path>`. If found, render content using `markdown` (for `.md`) or as-is (for `.txt`) and include in the template.
*   **Blob View (`GET /<repo_name>/blob/<ref>/<path>`)**:
    *   Logic: `git cat-file blob <ref>:<path>`. Return raw text/binary.
*   **Commit History (`GET /<repo_name>/commits/<ref>`)**:
    *   Logic: `git log --pretty=format:"%H%x00%an%x00%at%x00%s" -z -n 100 <ref>`. Parse output.

### 6.2. Git Smart HTTP Handling (`ANY /<repo_name>.git/*`)
*   **Path Parsing:** Regex match to extract `<repo_name>`.
*   **Env Setup:**
    *   `GIT_PROJECT_ROOT`: Absolute path to `repos` dir.
    *   `GIT_HTTP_EXPORT_ALL`: "1" (allows serving without `git-daemon-export-ok` file).
    *   `PATH_INFO`: The part of URL after `/repos`.
    *   `CONTENT_TYPE`: Forwarded from request.
    *   `QUERY_STRING`: Forwarded from request.
*   **Execution:**
    *   `subprocess.Popen` with `stdin=request.stream`, `stdout=PIPE`, `stderr=PIPE`.
    *   Stream stdout back to Flask response with correct Content-Type.

### 6.3. CLI: Import Repo
*   Command: `python src/app.py --import-repo <name> --owner <user>`
*   Logic:
    *   Check if `<repo_path>/<name>.git` exists.
    *   Check if `<name>` is already in DB. (If so, abort).
    *   Check if `<user>` exists in DB.
    *   `INSERT INTO repos ...`.

## 7. Implementation Details

### 7.1. Git Subprocess Strategy
To ensure robustness and avoid shell injection:
*   **No Shell=True:** All commands will be passed as lists: `['git', 'ls-tree', ...]`.
*   **Output Parsing:** Use `-z` (null termination) for all git commands (`ls-tree`, `log`) to correctly handle filenames containing newlines or spaces.
*   **Encoding:** Decode stdout as `utf-8` with `errors='replace'` to handle non-UTF8 binary filenames gracefully. Careful handling of binary outputs for blobs.

### 7.2. CSS & Styling
*   **Philosophy:** Minimalist, semantic HTML.
*   **Layout:** CSS Grid/Flexbox for the main container (Sidebar + Content).
*   **Typography:** System fonts (`sans-serif`).
*   **Components:**
    *   Tables for file lists (no borders between rows, compact padding).
    *   Code blocks for file content (monospace, `overflow-x: auto`).
    *   Breadcrumbs for navigation (`repo > tree > folder`).

### 7.3. Session Secret Management
*   On application start (before `app.run`):
    1.  `conn = sqlite3.connect(...)`
    2.  `cursor.execute("SELECT value FROM system_config WHERE key='flask_secret_key'")`
    3.  If None:
        *   `secret = secrets.token_hex(32)`
        *   `INSERT ...`
    4.  `app.secret_key = secret`

## 8. Security Considerations
*   **Input Validation:**
    *   Repo names must match `^[a-zA-Z0-9._-]+$` and MUST NOT end with `.git`.
    *   Paths in tree view must be validated to prevent directory traversal (though git commands naturally scope to the repo, we must ensure we don't pass `..` arguments incorrectly).
*   **Password Storage:** SHA256(salt + password). The salt is a 16-byte random hex string.

## 9. Implementation Notes

### 9.1. Git Smart HTTP Bridge
The bridge to `git-http-backend` is implemented by populating a CGI-compatible environment:
*   `GIT_PROJECT_ROOT`: Absolute path to the repository directory.
*   `GIT_HTTP_EXPORT_ALL`: "1".
*   `PATH_INFO`: Extracted from the request path.
*   `REMOTE_USER`: Set to the authenticated `preferred_username` for write operations.
*   `REQUEST_METHOD`, `QUERY_STRING`, `CONTENT_TYPE`, `CONTENT_LENGTH`: Forwarded from the Flask request.

### 9.2. Empty Repository Handling
When a repository is detected as empty (via `git rev-parse --verify HEAD`), the web UI displays a "Quick Setup" guide. This guide dynamically uses the `default_branch` from the system configuration (falling back to `master`) to provide accurate initialization commands to the user.

### 9.3 Source Code Structure
All Python source files are located in the `src/` directory to keep the project root clean. The application resolves `data_path` to absolute paths to ensure assets (templates/static) are found correctly regardless of the execution context.

## 10. Dependency Management
*   `flask`: Web server.
*   `requests`: OIDC HTTP client.
*   `markdown`: Rendering READMEs.
*   **Standard Libs:** `sqlite3`, `subprocess`, `configparser`, `hashlib`, `os`, `sys`, `base64`, `argparse`.