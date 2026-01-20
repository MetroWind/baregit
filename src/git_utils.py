import subprocess
import os
from config import config

class GitError(Exception):
    pass

def getRepoPath(repo_name):
    # Security: Ensure repo_name doesn't have path traversal
    if os.path.sep in repo_name or '..' in repo_name:
        raise ValueError("Invalid repository name")
    
    # Per PRD: The repo dir name will be <repo_name>.git
    return os.path.join(config['paths']['repo_path'], f"{repo_name}.git")

def runGit(repo_name, command_args, encoding='utf-8', errors='replace'):
    repo_path = getRepoPath(repo_name)
    if not os.path.exists(repo_path):
        raise GitError(f"Repository {repo_name} not found")

    cmd = ['git', '-C', repo_path] + command_args
    
    kwargs = {
        'capture_output': True,
        'check': True
    }
    
    if encoding:
        kwargs['text'] = True
        kwargs['encoding'] = encoding
        kwargs['errors'] = errors
    else:
        kwargs['text'] = False

    try:
        result = subprocess.run(cmd, **kwargs)
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise GitError(f"Git command failed: {e.stderr.decode('utf-8', errors='replace') if e.stderr else str(e)}")

def getDefaultBranch(repo_name):
    try:
        # symbolic-ref HEAD usually points to refs/heads/master or refs/heads/main
        head_ref = runGit(repo_name, ['symbolic-ref', 'HEAD']).strip()
        return head_ref.replace('refs/heads/', '')
    except GitError:
        # Fallback if HEAD is detached or empty
        return "HEAD"

def isRepoEmpty(repo_name):
    # Checks if the repository has any commits
    try:
        runGit(repo_name, ['rev-parse', '--verify', 'HEAD'])
        return False
    except GitError:
        return True

def listTree(repo_name, ref, path=''):
    # git ls-tree -z -l <ref>:<path>
    # -z: null-terminated
    # -l: long format (permissions, type, size, name)
    
    target = f"{ref}:{path}" if path else ref
    try:
        output = runGit(repo_name, ['ls-tree', '-z', '-l', target])
    except GitError:
        return []

    entries = []
    # Output format: <mode> SP <type> SP <object> SP <size> TAB <file> NUL
    # But wait, with -l, it is: <mode> SP <type> SP <object> SP <size> TAB <file>
    
    # Because of -z, entries are separated by NUL.
    raw_entries = output.split('\0')
    
    for entry in raw_entries:
        if not entry:
            continue
            
        # The metadata is separated from filename by TAB
        if '\t' not in entry:
            continue
            
        metadata, filename = entry.split('\t', 1)
        # metadata: <mode> SP <type> SP <object> SP <size>
        # Note: <size> can be multiple spaces away or the metadata might have extra spaces.
        # split() with no arguments handles any whitespace.
        parts = metadata.split()
        
        if len(parts) < 4:
            continue
            
        mode, type_, object_hash, size = parts[0], parts[1], parts[2], parts[3]
        
        # Determine if it's a size or dash (for trees)
        size_display = size if size != '-' else ''
        
        entries.append({
            'mode': mode,
            'type': type_,
            'object': object_hash,
            'size': size_display,
            'name': filename,
            'path': f"{path}/{filename}".lstrip('/')
        })
        
    # Sort: trees before blobs, then by name
    entries.sort(key=lambda x: (x['type'] != 'tree', x['name']))
        
    return entries

def getBlobContent(repo_name, blob_hash):
    # Returns raw bytes
    repo_path = getRepoPath(repo_name)
    cmd = ['git', '-C', repo_path, 'cat-file', 'blob', blob_hash]
    try:
        result = subprocess.run(cmd, capture_output=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return b""

def getCommitLog(repo_name, ref, limit=100):
    # git log --pretty=format:"%H%x00%an%x00%at%x00%s" -z -n <limit> <ref>
    # %H: Hash, %an: Author Name, %at: Author Time (unix), %s: Subject
    
    args = [
        'log',
        f'--pretty=format:%H%x00%an%x00%ar%x00%at%x00%s',
        '-z',
        '-n', str(limit),
        ref
    ]
    
    try:
        output = runGit(repo_name, args)
    except GitError:
        return []
        
    commits = []
    raw_entries = output.split('\0')
    
    # The output is flat list of fields due to %x00 separator between fields AND -z between records
    # But wait, -z puts a NUL after each commit.
    # The format string puts NULs between fields.
    # So actually it's just a long stream of NUL-separated values.
    # Fields per commit: 5 (Hash, Name, RelativeDate, Timestamp, Subject)
    
    # Let's group by 5
    # Filter empty strings (end of list)
    data = [x for x in raw_entries if x]
    
    for i in range(0, len(data), 5):
        if i + 4 >= len(data):
            break
        commits.append({
            'hash': data[i],
            'author': data[i+1],
            'date_rel': data[i+2],
            'timestamp': data[i+3],
            'subject': data[i+4]
        })
        
    return commits

def initBareRepo(repo_name):
    repo_path = getRepoPath(repo_name)
    if os.path.exists(repo_path):
        raise GitError("Repository already exists")
    
    os.makedirs(repo_path)
    
    # If default branch is configured, use it
    default_branch = config['git'].get('default_branch')
    args = ['init', '--bare']
    if default_branch:
        args.append(f'--initial-branch={default_branch}')
        
    subprocess.run(['git'] + args + [repo_path], check=True)

def deleteRepo(repo_name):
    import shutil
    repo_path = getRepoPath(repo_name)
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

def getRefs(repo_name):
    # Returns a list of ref names (branches and tags)
    # git for-each-ref --format='%(refname:short)' refs/heads refs/tags
    try:
        output = runGit(repo_name, ['for-each-ref', '--format=%(refname:short)', 'refs/heads', 'refs/tags'])
        return output.splitlines()
    except GitError:
        return []

def splitRefPath(repo_name, full_path):
    # Tries to determine where the ref ends and path starts.
    # Strategy: Match against known refs, longest match wins.
    # If no match found, assume first component is ref (fallback).
    
    refs = getRefs(repo_name)
    # Sort by length descending to match longest first
    refs.sort(key=len, reverse=True)
    
    for ref in refs:
        if full_path == ref:
             return ref, ""
        if full_path.startswith(ref + '/') :
             return ref, full_path[len(ref)+1:]
             
    # Fallback: Treat first component as ref
    parts = full_path.split('/', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return parts[0], ""
