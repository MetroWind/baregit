import configparser
import os
import sys

def load_config(config_file=None):
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

    if config_file:
        if os.path.exists(config_file):
            config.read(config_file)
        else:
            print(f"Warning: Configuration file {config_file} not found. Using defaults.")
    else:
        # Default behavior: try baregit.ini silently
        if os.path.exists('baregit.ini'):
            config.read('baregit.ini')

    return config

config = load_config()

def reload_config_from_file(path):
    global config
    new_conf = load_config(path)
    # Update the global object in place to affect importers
    for section in new_conf.sections():
        if not config.has_section(section):
            config.add_section(section)
        for key, val in new_conf.items(section):
            config[section][key] = val
