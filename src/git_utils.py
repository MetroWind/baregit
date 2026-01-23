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
        
    entries.sort(key=lambda x: (x['type'] != 'tree', x['name']))
        
    # Enrich with latest commit info
    paths = [e['path'] for e in entries]
    commits = getLatestCommits(repo_name, ref, paths)
    
    for entry in entries:
        info = commits.get(entry['path'])
        if info:
            entry['commit_hash'] = info['hash']
            entry['commit_subject'] = info['subject']
            entry['commit_date'] = info['date_rel'] # Or use date_ts
            entry['commit_timestamp'] = info['timestamp']
        else:
            entry['commit_hash'] = ''
            entry['commit_subject'] = ''
            entry['commit_date'] = ''
            entry['commit_timestamp'] = 0

    return entries

def getLatestCommits(repo_name, ref, paths):
    if not paths:
        return {}
        
    repo_path = getRepoPath(repo_name)
    # Batching to avoid command line length limits
    BATCH_SIZE = 50
    results = {}
    
    for i in range(0, len(paths), BATCH_SIZE):
        batch = paths[i:i+BATCH_SIZE]
        needed = set(batch)
        
        # Format: START:<hash>%x00<subject>%x00<date_rel>%x00<timestamp>
        # We rely on -z to separate files with NUL
        cmd = [
            'git', '-C', repo_path, 'log', '-z', '--name-only', 
            '--format=START:%H%x00%s%x00%ar%x00%at', 
            ref, '--'
        ] + batch
        
        try:
            # use Popen to stream and stop early
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=False) as proc:
                # Stream the NUL-terminated output to find the latest commit for each file.
                # We stop reading as soon as we find all files in the batch.
                buffer = b''
                current_commit = None
                
                while needed:
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    
                    buffer += chunk
                    while b'\0' in buffer:
                        token_bytes, buffer = buffer.split(b'\0', 1)
                        token = token_bytes.decode('utf-8', errors='replace')
                        
                        if token.startswith('START:'):
                            # New commit
                            # Format: START:<hash> then next tokens are subject, date, ts
                            # Wait, my format string puts %x00 between fields.
                            # So tokens will be: [START:hash, subject, date, ts, file1, file2...]
                            # Actually:
                            # START:hash \0 subject \0 date \0 ts \0 \nfile1 \0 file2 ...
                            
                            parts = token.split(':', 1)
                            if len(parts) == 2:
                                # We are at the start of a commit.
                                # The next 3 tokens are the rest of the metadata.
                                # But we are in a loop popping tokens.
                                # We need a state machine.
                                current_commit = {'hash': parts[1]}
                                # We need to fetch next 3 tokens for this commit metadata
                                # But we need to ensure we have them in buffer?
                                # The "while b'\0' in buffer" loop handles fetching tokens sequentially.
                                # So we just set a state "expecting_metadata_1" etc?
                                # Or simpler: just keep a counter?
                                
                                # Let's use a list as a stack/queue of fields for current commit
                                # If current_commit is incomplete, fill it.
                                # If complete, token is a filename.
                                continue

                        if current_commit:
                            if 'subject' not in current_commit:
                                current_commit['subject'] = token
                            elif 'date_rel' not in current_commit:
                                current_commit['date_rel'] = token
                            elif 'timestamp' not in current_commit:
                                current_commit['timestamp'] = token
                            else:
                                # Filename
                                fname = token.strip()
                                if fname in needed:
                                    results[fname] = current_commit
                                    needed.remove(fname)
                                    
                # If we found all, terminate
                if not needed:
                    proc.terminate()
                    
        except Exception:
            pass
            
    return results

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
    
    # The output is flat list of fields due to %x00 separator between fields.
    # -z separates commits with NUL, and our format string uses NUL between fields.
    # So it is a continuous stream of NUL-separated values.
    
    # Remove the last empty string if it exists (due to trailing NUL)
    if raw_entries and raw_entries[-1] == '':
        raw_entries.pop()
        
    data = raw_entries
    
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

def getCommitDetails(repo_name, commit_hash):
    # 1. Get Metadata
    # Format: Hash, Author Name, Author Email, Date, Subject, Body
    fmt = "%H%x00%an%x00%ae%x00%ad%x00%s%x00%b"
    cmd_meta = ['show', '-s', f'--format={fmt}', '-z', commit_hash]
    
    try:
        output_meta = runGit(repo_name, cmd_meta)
    except GitError:
        return None

    parts = output_meta.split('\0')
    if len(parts) < 6:
        return None

    # 2. Get Diff
    # We use --pretty=format: to suppress the log message in the diff output
    cmd_diff = ['show', '--pretty=format:', commit_hash]
    try:
        output_diff = runGit(repo_name, cmd_diff)
    except GitError:
        output_diff = "Could not retrieve diff."

    return {
        'hash': parts[0],
        'author': parts[1],
        'email': parts[2],
        'date': parts[3],
        'subject': parts[4],
        'body': parts[5],
        'diff': output_diff.strip()
    }

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
