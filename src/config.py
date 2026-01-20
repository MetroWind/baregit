import configparser
import os
import sys

def load_config(config_file='config.ini'):
    config = configparser.ConfigParser()
    
    # Defaults
    config['server'] = {'host': '127.0.0.1', 'port': '5000', 'debug': 'false'}
    config['paths'] = {
        'data_path': '/var/lib/baregit',
        'repo_path': '/var/lib/baregit/repos',
        'git_http_backend': '/usr/libexec/git-core/git-http-backend'
    }
    # Default branch empty implies using git's internal default
    config['git'] = {'default_branch': ''}
    config['oidc'] = {
        'auth_root_url': '',
        'client_id': '',
        'client_secret': ''
    }

    if os.path.exists(config_file):
        config.read(config_file)
    else:
        print(f"Warning: Configuration file {config_file} not found. Using defaults.")

    return config

# Load config once to be imported by other modules
config = load_config()
