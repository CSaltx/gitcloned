import argparse
import collections
import configparser
from datetime import datetime
import grp, pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
import zlib


argparser = argparse.ArgumentParser(description="the best content tracker")

argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
argsp = argsubparsers.add_parser("init", help="Initialize a new, empty repository.")
argsp.add_argument("path", metavar="directory", nargs="?", default=".", help="Where do you want to create repository?")
argsubparsers.required = True
def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)
    match args.command:
        case "add": cmd_add(args)
        case "cat-file": cmd_cat_file(args)
        case "check-ignore": cmd_check_ignore(args)
        case "checkout": cmd_checkout(args)
        case "commit": cmd_commit(args)
        case "hash-object": cmd_hash_object(args)
        case "init": cmd_init(args)
        case "log": cmd_log(args)
        case "ls-files": cmd_ls_files(args)
        case "ls-tree": cmd_ls_tree(args)
        case "merge": cmd_merge(args)
        case "rebase": cmd_rebase(args)
        case "rev-parse": cmd_rev_parse(args)
        case "rm": cmd_rm(args)
        case "show-ref": cmd_show_ref(args)
        case "status": cmd_status(args)
        case "tag": cmd_tag(args)
        case _: print("Error: Command doesn't exist")

def cmd_init(args):
    repo_create(args.path)

def repo_path(repo, *path):
    return os.path.join(repo.gitdir, *path)
    
def repo_dir(repo, *path, mkdir=False):
    path = repo_path(repo, *path)

    if os.path.exists(path):
        if (os.path.isdir(path)):
            return path
        else:
            raise Exception("Not a directory %s" % path)

    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None

def repo_file(repo, *path, mkdir=False):
    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)
    
def repo_create(path):

    repo = GitRepository(path, True)

    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception(f"{path} is not a directory!")
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception(f"{path} is not empty!")
    else:
        os.makedirs(repo.worktree)
    
    assert(repo_dir(repo, "branches", mkdir=True))
    assert(repo_dir(repo, "objects", mkdir=True))
    assert(repo_dir(repo, "refs", "tags", mkdir=True))
    assert(repo_dir(repo, "refs", "heads", mkdir=True))
    
    with open(repo_file(repo, "description"), "w") as f:
        f.write("Unnamed repository; edit this file 'description' to name the repository.\n")

    with open(repo_file(repo, "HEAD"), "w") as f:
        f.write("ref: refs/heads/master\n")
    
    with open(repo_file(repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)
    return repo

def repo_default_config():
    ret = configparser.ConfigParser()

    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret

def repo_find(path=".", required=True):
    path = os.path.realpath(path)

    if os.path.isdir(os.path.join(path, '.git')):
        return GitRepository(path)
        
    parent = os.path.realpath(os.path.join(path, ".."))
    if parent == path:
        if required:
            raise Exception(f"No git directory in given path.")
        else:
            return None
    
    return repo_find(parent, required)

def object_read(repo, hash):
    path = repo_file(repo, "objects", hash[0:2], hash[2:])

    if not os.path.isfile(path):
        return None
    
    with open (path, "rb") as f:
        raw = zlib.decompress(f.read())

        space = raw.find(b' ')
        fmt = raw[0:space]

        zero = raw.find(b'\x00', space)
        size = int(raw[space:zero].decode('ascii'))
        if size != len(raw)-zero-1:
            raise Exception("Malformed object {0}: bad length".format(hash))
        
        match fmt:
            case b'commit': c = GitCommit
            case b'tree': c = GitTree
            case b'tag': c = GitTag
            case b'blob': c = GitBlob
            case _:
                raise Exception("Unknown type {0} for object {1}".format(fmt.decode("ascii"), hash))
        return c(raw[zero+1:])
        
def object_find(repo, name, fmt=None, follow=True):
    return name

def object_write(obj, repo=None):
    data = obj.serialize()

    result = obj.fmt + b' ' + str(len(data)).encode() + b'\x00' + data

    sha = hashlib.sha1(result).hexdigest()

    if repo:
        path = repo_file(repo, "objects", sha[0:2], sha[2:], mkdir=True)

        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(zlib.compress(result))

    return sha

argsp = argsubparsers.add_parser('cat-file', help='Provide content for repository objects.')
argsp.add_argument("type", metavar="type", choices=['blob', 'commit', 'tag', 'tree'], help='Specify Type.')
argsp.add_argument('object', metavar='object', help='The Object to Display.')

def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())

def cat_file(repo, obj, fmt=None):
    obj = object_read(repo, obj)
    sys.stdout.buffer.write(obj.serialize())

argsp = argsubparsers.add_parser(
    "hash-object",
    help="Compute object ID and optionally creates a blob from a file")
argsp.add_argument('-w', dest="write",
                   action="store_true",
                   help="Actually write the object into the repo")
argsp.add_argument('-t', metavar='type', dest='type', choices=['blob', 'commit', 'tag', 'tree'], default='blob', help='Specify type.')
argsp.add_argument('path', help='Read object from <file>')

def cmd_hash_object(args):
    if args.write:
        repo = repo_find()
    else:
        repo = None

    with open(args.path, 'rb') as fd:
        sha = object_hash(fd, args.type.encode(), repo=repo)
        print(sha)

def object_hash(fd, fmt, repo=None):
    data = fd.read()

    match fmt:
        case b'commit': obj = GitCommit(data)
        case b'tree': obj = GitTree(data)
        case b'tag': obj = GitTag(data)
        case b'blob': obj = GitBlob(data)
        case _:
            raise Exception(f"Unknown type {fmt}")

    return object_write(obj, repo)

def kvlm_parse(raw, start=0, dct=None):
    if not dct:
        dct = collections.OrderedDict()

    space = raw.find(b' ', start)
    newline = raw.find(b'\n', start)

    if space < 0 or newline < space:
        assert(newline == start)
        dct[None] = raw[start+1:]
        return dict
    
    keyword = raw[start:space]

    end = start
    while True:
        end = raw.find(b'\n', end+1)
        if raw[end+1] != ord(' '): 
            break
    
    value = raw[space+1:end].replace(b'\n ', b'\n')

    if keyword in dct:
        if type(dct[keyword]) == list:
            dct[keyword].append(value)
        else:
            dct[keyword] = [dct[keyword], value]
    else:
        dct[keyword] = value
    
    return kvlm_parse(raw, start=end+1, dct=dct)

def kvlm_serializze(kvlm):
    res = b''

    for k in kvlm.keys():
        if k != None:
            values = kvlm[k]
            if type(values) != list:
                values = [ values ]
            for val in values:
                res += k + b' ' + val.replace(b'\n ', b'\n') + b'\n'
    res += b'\n' + kvlm[None] + b'\n'
    return res
    
argsp = argsubparsers.add_parser('log', help='Display history of a given commit.')
argsp.add_argument('commit', default='HEAD', nargs='?', help='Commit to start at')

def cmd_log(args):
    repo = repo_find()

    print("digraph wyaglog{")
    print("  node[shape=rect]")
    log_graphviz(repo, object_find(repo, args.commit), set())
    print("}")

def log_graphviz(repo, sha, seen):

    if sha in seen:
        return
    seen.add(sha)

    commit = object_read(repo, sha)
    short_hash = sha[0:8]
    message = commit.kvlm[None].decode("utf8").strip()
    message = message.replace("\\", "\\\\")
    message = message.replace("\"", "\\\"")

    if "\n" in message:
        message = message[:message.index("\n")]

    print("  c_{0} [label=\"{1}: {2}\"]".format(sha, sha[0:7], message))
    assert commit.fmt==b'commit'

    if b'parent' not in commit.kvlm.keys():
        return

    parents = commit.kvlm[b'parent']

    if type(parents) != list:
        parents = [ parents ]

    for p in parents:
        p = p.decode("ascii")
        print ("  c_{0} -> c_{1};".format(sha, p))
        log_graphviz(repo, p, seen)

class GitRepository (object):

    worktree = None
    gitdir = None
    conf = None

    def __init__ (self, path, force=False):
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")

        if not (force or os.path.isdir(self.gitdir)):
            raise Exception(f"Not a Git repository {path}")
        
        # Read configuration file in .git/config
        self.conf = configparser.ConfigParser()
        cf = repo_file(self, "config")

        if cf and os.path.exists(cf):
            self.conf.read([cf])
        elif not force:
            raise Exception("Configuration file missing")
        
        if not force:
            vers = int(self.conf.get('core', 'repositoryformatversion'))
            if vers != 0:
                raise Exception(f"Unsupported repositoryformatversion {vers}")

class GitObject (object):

    def __init__(self, data=None):
        if data != None:
            self.deserialize(data)
        else:
            self.init()
    
    def serialize(self, repo):
        raise Exception("Unimplemented ATM")
    
    def deserialize(self, hash):
        raise Exception("Unimplemented ATM")

    def init(self):
        pass

class GitBlob(GitObject):
    fmt=b'blob'

    def serialize(self, repo=None):
        return self.blobdata
    
    def deserialize(self, data):
        self.blobdata = data

class GitCommit(GitObject):
    fmt = b'commit'
    def __init__(self):
        self.kvlm = dict()

    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)

    def serialize(self, data):
        return kvlm_serializze(data)
