# BareGit: A git web interface in Python

* Uses flask and Jinja.
* Just use the flask dev server for deployment. It’s fine as long as
  it doesn’t leak debug info on error.
* Don’t use bootstrap for styling. Just use normal CSS.
* Allows HTTP push and clone to the repositories on the server by
  piping with `git-http-backend`. The path of `git-http-backend`
  should be (optionally) configurable, and defaults to
  `/usr/lib/git-core/git-http-backend`.
* Users can browse the files in the repositories on the web interface.
* Users can also create new (bare) repositories on the web interface.
* Default git branch name should be configurable. If not configured,
  use the git default.
* Repo names should be globally unique. The repo dir name will be
  `<repo_name>.git`. The repo name itself must not ends with `.git`.
* Authentication for the web UI: through an external OpenID Connect
  server (keycloak) using the “Authorization Code Flow”. Specifically,
  there should be a configuration for a auth root URL for the OpenID
  Connect service. Then querying the URL `<auth root
  url>/.well-known/openid-configuration` will give a JSON that list
  all the auth-related endpoints. See
  https://www.keycloak.org/securing-apps/oidc-layers for details. Use
  `requests` to communicate with the OIDC server. I already have a
  running keycloak server. The OpenID client ID and client secret will
  be provided in the config file.
* Git push/clone authentication: HTTP basic. Once a user is
  authenticated on the web UI, the user can set a user name and
  password for the git operations, which can be different from the
  once from the OIDC server. (and obviously the git user names should
  be unique.) Use the builtin hashlib to salt and hash
  the password.
* The users should be mapped to UID on the OIDC server. The
  preferred_username with be the displayed user name on the web UI.
  This would allow the user to change their name on the OIDC server
  without breaking the linkage.
* All repos are public. All users can read all repos. Only owner of
  repo can write to repo.
* Use a sqlite file to store user data (preferences, salted and hashed
  passwords, etc.), but don’t use sqlalchemy. Just use the builtin
  sqlite3 library. The path of the database file is configurable in
  the config file. But it also should have a default.
* Repository storage path should be configurable.
* Use subprocess to call the git executable to get lists of files and
  commits, etc. Use formatted output (e.g. null-delimiters) to
  improvement reliability.
* Config should be read from a INI file, and parsed with
  `configparser`.
* As the user navigating the git tree, whenever there is a README.md
  or README.txt, render it into the web UI (using the markdown library
  for `.md` files). This is similar to GitHub.
* The session secret key should be automatically generated and stored
  in the database (if not found in the database).
* If a repo is found in the path where the repos are stored, but not
  found in sqlite. Do not list the repo. A CLI argument (with the same
  executable as the server) should be provided to assign these repos
  to a user (by user name) and thus bring them into the database.
* URLs: Web UI URLs are `/<repo_name>/...`. Git operation URLs are
  `/<repo_name>.git/...`.
