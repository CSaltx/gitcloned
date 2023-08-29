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

'''
* Object read func
** Reads obj, hash from repo inputted and outputs the GitObj that changes based on hash
'''
def object_read(repo, sha):
    path = repo_file(repo, "objects", sha[0:2], sha[2:])

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
            case _: raise Exception("Unknown type {0} for object {1}".format(fmt.decode("ascii"), hash))
        return c(raw[zero+1:])
        
def object_find(repo, name, fmt=None, follow=True):
    sha = object_resolve(repo, name)

    if not sha:
        # Not found
        raise Exception(f'No reference {name}')
    
    if len(sha) > 1:
        raise Exception("Ambiguous reference {0}: Candidates are:\n - {1}.".format(name,  "\n - ".join(sha)))
    
    sha = sha[0]

    if not fmt:
        return sha

    while True:
        obj = object_read(repo, sha)

        if obj.fmt == fmt:
            return sha
        
        if not follow:
            return None
        
        if obj.fmt == b'tag':
            sha = obj.kvlm[b'object'].decode('ascii')
        elif obj.fmt == b'commit' and fmt == b'tree':
            sha = obj.kvlm[b'tree'].decode('ascii')
        else:
            return None

def object_resolve(repo, name):
    candidates = []
    regex = re.compile(r"^[0-9A-Fa-f]{4,40}$")

    if not name.strip():
        return None

    if name == "HEAD":
        return [ ref_resolve(repo, "HEAD") ]
    
    if regex.match(name):
        name = name.lower()
        prefix = name[0:2]
        path = repo_dir(repo, "objects", prefix, mkdir=False)
        if path:
            remainder = name[2:]
            for f in os.listdir(path):
                if f.startswith(remainder):
                    candidates.append(prefix + f)
    
    tag = ref_resolve(repo, 'refs/tag/' + name)
    if tag:
        candidates.append(tag)
    
    branch = ref_resolve(repo, 'refs/heads/' + name)
    if branch:
        candidates.append(branch)
        
    return candidates

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
        return dct
    
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
    print(f'{commit.kvlm[None]=}')
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

def tree_parse_one(raw, start=0):
    spc = raw.find(b' ', start)
    assert spc-start == 5 or spc-start == 6

    mode = raw[start:spc]
    if len(mode) == 5:
        mode = b' ' + mode
    
    null = raw.find(b'\x00', spc)

    path = raw[spc+1:null]

    sha = format(int.from_bytes(raw[null+1:null+21], "big"), "040x")
    return null+21, GitTreeLeaf(mode, path.decode("utf-8"), sha)

def tree_parse(raw):
    pos = 0
    m = len(raw)
    ret = []
    while pos < m:
        pos, data = tree_parse_one(raw, pos)
        ret.append(data)
    return ret

def tree_leaf_sort_key(leaf: object):
    if leaf.mode.startswith(b'10'):
        return leaf.path
    else:
        return leaf.path + "/"

def tree_serialize(obj):
    ret = b''
    obj.items.sort(key=tree_leaf_sort_key)
    for i in obj.items:
        ret += i.mode
        ret += b' '
        ret += i.path.encode('utf8')
        ret += b'\x00'
        sha = int(i.sha, 16)
        ret += sha.to_bytes(20, byteorder='big')
    return ret

argsp = argsubparsers.add_parser('ls-tree', help="Print a tree obj")
argsp.add_argument('-r', dest="recursive", action="store_true", help="Recurse into sub trees")
argsp.add_argument('tree', help='A "tree" object')

def cmd_ls_tree(args):
    repo = repo_find()
    ls_tree(repo, args.tree, args.recursive)

def ls_tree(repo, tree, recur=None, prefix=""):
    sha = object_find(repo, tree, fmt=b'tree')
    obj = object_read(repo, sha)
    for item in obj.items:
        if len(item.mode) == 5:
            mode = item.mode[:1]
        else:
            mode = item.most[:2]
    
    match mode:
        case b'04': mode = "tree"
        case b'10': mode = "blob" # A regular file.
        case b'12': mode = "blob" # A symlink. Blob contents is link target.
        case b'16': mode = "commit" # A submodule
        case _: raise Exception(f"Weird tree leaf mode {item.mode}")
    
    if (not recur and mode=="tree"):
        print("{0} {1} {2}\t{3}".format(
                "0" * (6 - len(item.mode)) + item.mode.decode("ascii"),
                type,
                item.sha,
                os.path.join(prefix, item.path)))
    else:
        ls_tree(repo, item.sha, recur, os.path.join(prefix, item.path))

'''
* Git Checkout Code
'''

argsp = argsubparsers.add_parser('checkout', help="Checkout a commit inside of a directory.")
argsp.add_argument('commit', help="The commit or tree to checkout")
argsp.add_argument('path', help="The empty dir to checkout to")

def cmd_checkout(args):
    repo = repo_find()
    obj = object_read(repo, object_find(repo, args.commit))
    # if commit, get the tree associated
    if obj == b'commit':
        obj = object_read(repo, obj.kvlm[b'tree'].decode('ascii'))
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception(f'Path {args.path} is not a directory.')
        if os.listdir(args.path):
            raise Exception(f'Path {args.path} is not empty.')
    else:
        os.makedirs(args.path)
    
    tree_checkout(repo, obj, os.path.realpath(args.path))

def tree_checkout(repo, tree, path):
    for item in tree.items:
        obj = object_read(repo, item.sha)
        dest = os.path.join(path, item.path)
        if item.mode == b'tree':
            os.mkdir(dest)
            tree_checkout(repo, obj, dest)
        elif item.mode == b'blob':
            with open(dest, 'wb') as f:
                f.write(obj.data)
        else:
            raise Exception(f'Unknown tree item mode {item.mode}')
            # ideally support symlinks in future
'''
'''


'''
* All code in this block will be for refs, see .git/refs for reference (pun intended)
'''

def ref_resolve(repo, ref):
    path = repo_file(repo, ref)
    # file doesn't exist yet due to lack of init commit
    if not os.path.isfile(path):
        return None

    with open(path, 'r') as f:
        data = f.read()[::-1]
    
    if data.startswith('ref: '):
        return ref_resolve(repo, data[5:])
    else:
        return data

# func to list refs recursively, build path then iterate through path and recursively call dirs and resolve valid paths
def list_refs(repo, path=None):
    if not path:
        path = repo_dir(repo, "refs")
    ret = collections.OrderedDict()
    for file in sorted(os.listdir(path)):
        new_path = os.path.join(path, file)
        if os.file.isdir(new_path):
            ret[file] = list_refs(repo, new_path)
        else:
            ret[file] = ref_resolve(repo, new_path)
    return ret

arsp = argsubparsers.add_parser('show-refs', help='List out references.')

def cmd_show_refs(args):
    repo = repo_find()
    refs = list_refs(repo)
    show_refs(repo, refs, prefix="refs")
    
def show_refs(repo, refs, with_hash=True, prefix=""):
    for k, v in refs.items():
        if type(v) == str:
            print ("{0}{1}{2}".format(
                v + " " if with_hash else "",
                prefix + "/" if prefix else "",
                k))
        else:
            show_refs(repo, v, with_hash=with_hash, prefix="{0}{1}{2}".format(prefix, "/" if prefix else "", k))

'''
'''

'''
* All code in section is for tag command, aka git tag v1234 e09263e, lightweight tags
'''

argsp = argsubparsers.add_parser('tag', help='List and create tags')

argsp.add_argument('-a', action='store_true', dest='create_tag_object', help='Create a tag object?')
argsp.add_argument('name', nargs='?', help="Name for the new tag.")
argsp.add_argument('object', default='HEAD', nargs='?', help='The object that the tag will reference.')

def cmd_tag(args):
    repo = repo_find()

    if args.name:
        tag_create(repo, args.name, args.object, type="object" if args.create_tag_object else "ref")
    else:
        refs=list_refs(repo)
        show_refs(repo, refs["tags"], with_hash=False)

def tag_create(repo, name, ref, create_tag_object=False):
    sha = object_find(repo, ref)

    if create_tag_object:
        obj = GitTag(repo)
        obj.kvlm = collections.OrderedDict()
        obj.kvlm[b'object'] = sha.encode()
        obj.kvlm[b'type'] = b'commit'
        obj.kvlm[b'tag'] = name.encode()
        obj.kvlm[b'tagger'] = b'Coby coby@schumitzky.dev'
        obj.kvlm['None'] = b'A tag generated by wyag (coby)!'

        obj_sha = object_write(obj)

        ref_create(repo, "tags/" + name, obj_sha)
    else:
        ref_create(repo, "tags/" + name, sha)

def ref_create(repo, path, sha):
    with open(repo_file(repo, "refs/" + path), "w") as fp:
        fp.write(sha + '\n')

'''
'''

argsp = argsubparsers.add_parser(
    "rev-parse",
    help="Parse revision (or other objects) identifiers")

argsp.add_argument("--wyag-type",
                   metavar="type",
                   dest="type",
                   choices=["blob", "commit", "tag", "tree"],
                   default=None,
                   help="Specify the expected type")

argsp.add_argument("name",
                   help="The name to parse")

def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None
    
    repo = repo_find()
    
    
    print(object_find(repo, args.name, fmt, follow=True))

'''
* Below is parser to index files into the objs created earlier (gitIndexEntry and GitIndex)
* params repo => obj that we are parsing
'''

def index_read(repo):
    index_file = repo_file(repo, "index")

    if not os.path.exists(index_file):
        return GitIndex()
    
    with open(index_file, 'rb') as f:
        raw = f.read()
    
    header = raw[:12]
    signature = header[:4]
    assert signature == b"DIRC"
    version = int.from_bytes(header[4:8], "big")
    assert version == 2, "Functionality only supports index file version 2"
    count = int.from_bytes(header[8:12], "big")

    entries = []

    content = raw[12:]
    idx = 0
    for i in range(0, count):
        ctime_s =  int.from_bytes(content[idx: idx+4], "big")
        ctime_ns = int.from_bytes(content[idx+4: idx+8], "big")

        mtime_s = int.from_bytes(content[idx+8: idx+12], "big")
        mtime_ns = int.from_bytes(content[idx+12: idx+16], "big")

        dev = int.from_bytes(content[idx+16: idx+20], "big")

        ino = int.from_bytes(content[idx+20: idx+24], "big")

        unused = int.from_bytes(content[idx+24: idx+26], "big")
        assert 0 == unused

        mode = int.from_bytes(content[idx+26: idx+28], "big")
        mode_type = mode >> 12
        assert mode_type in [0b1000, 0b1010, 0b1110]
        mode_perms = mode & 0b0000000111111111

        uid = int.from_bytes(content[idx+28: idx+32], "big")

        gid = int.from_bytes(content[idx+32: idx+36], "big")

        fsize = int.from_bytes(content[idx+36: idx+40], "big")

        sha = format(int.from_bytes(content[idx+40: idx+60], "big"), "040x")

        flags = int.from_bytes(content[idx+60: idx+62], "big")
        flag_assume_valid = (flags & 0b1000000000000000) != 0
        flag_extended = (flags & 0b0100000000000000) != 0
        assert not flag_extended
        flag_stage =  flags & 0b0011000000000000

        name_length = flags & 0b0000111111111111

        idx += 62

        if name_length < 0xFFF:
            assert content[idx + name_length] == 0x00
            raw_name = content[idx:idx+name_length]
            idx += name_length + 1
        else:
            print("Notice: Name is 0x{:X} bytes long.".format(name_length))
            null_idx = content.find(b'\x00', idx + 0xFFF)
            raw_name = content[idx: null_idx]
            idx = null_idx + 1


        name = raw_name.decode("utf8")

        idx = 8 * ceil(idx / 8)

        entries.append(GitIndexEntry(ctime=(ctime_s, ctime_ns),
                                     mtime=(mtime_s,  mtime_ns),
                                     dev=dev,
                                     ino=ino,
                                     mode_type=mode_type,
                                     mode_perms=mode_perms,
                                     uid=uid,
                                     gid=gid,
                                     fsize=fsize,
                                     sha=sha,
                                     flag_assume_valid=flag_assume_valid,
                                     flag_stage=flag_stage,
                                     name=name))

    return GitIndex(version=version, entries=entries)


argsp = argsubparsers.add_parser('ls-files', help='List all staged files')
argsp.add_argument('--verbose', action="store_true", help="Show everything.")

def cmd_ls_files(args):
    repo = repo_find()
    index = index_read(repo)
    if args.verbose:
        print(f"Index file format v{index.version}, containing {len(index.entries)} entries.")
    for e in index.entries:
        print(e.name)
        if args.verbose:
            print("  {} with perms: {:o}".format({ 0b1000: "regular file",0b1010: "symlink",0b1110: "git link" }[e.mode_type],e.mode_perms))
            print("  on blob: {}".format(e.sha))
            print("  created: {}.{}, modified: {}.{}".format( datetime.fromtimestamp(e.ctime[0]), e.ctime[1], datetime.fromtimestamp(e.mtime[0]), e.mtime[1]))
            print("  device: {}, inode: {}".format(e.dev, e.ino))
            print("  user: {} ({})  group: {} ({})".format(pwd.getpwuid(e.uid).pw_name,e.uid,grp.getgrgid(e.gid).gr_name,e.gid))
            print("  flags: stage={} assume_valid={}".format(e.flag_stage, e.flag_assume_valid))

argsp = argsubparsers.add_parser("check-ignore", help="Check path(s) against ignore rules.")
argsp.add_argument("path", nargs="+", help="Path for check")

def cmd_check_ignore(args):
    repo = repo_find()
    rules = gitignore_read(repo)
    for path in args.path:
        if check_ignore(path, rules):
            print(path)

def gitignore_parse(raw: str) -> tuple[str, bool]:
    raw = raw.strip()
    if not raw or raw[0] == "#":
        return None
    elif raw[0] == "!":
        return (raw[1:], False)
    elif raw[0] == "//":
        return (raw[1:], True)
    else:
        return (raw, True)

def gitignore_parsed(lines):
    ret = []

    for line in lines:
        parsed = gitignore_parse(line)
        if parsed:
            ret.append(line)
    return ret

def gitignore_read(repo):
    ret = GitIgnore([], {})

    repo_file = os.path.join(repo.gitdir, "info/exclude")
    if os.path.exists(repo_file):
        with open(repo_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    if "XDG_CONFIG_HOME" in os.environ:
        config_home = os.environ["XDG_CONFIG_HOME"]
    else:
        config_home = os.path.expanduser("~/.config")
    global_file = os.path.join(config_home, "git/ignore")

    if os.path.exists(global_file):
        with open(global_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    index = index_read(repo)

    for entry in index.entries:
        if entry.name == ".gitignore" or entry.name.endswith("/.gitignore"):
            dir_name = os.path.dirname(entry.name)
            contents = object_read(repo, entry.sha)
            lines = contents.blobdata.decode("utf8").splitlines()
            ret.scoped[dir_name] = gitignore_parse(lines)
    return ret

def check_ignore_rules(rules, path):
    result = None

    for (pattern, value) in rules:
        if fnmatch(path, pattern):
            result = value
    return result

def check_ignore_scoped(rules, path):
    parent = os.path.dirname(path)
    while True:
        if parent in rules:
            result = check_ignore_rules(rules[parent], path)
            if result != None:
                return result
        if parent == "":
            break
        parent = os.path.dirname(parent)
    return None

def check_ignore_absolute(rules, path):
    parent = os.path.dirname(path)
    for ruleset in rules:
        result = check_ignore_rules(ruleset, path)
        if result != None:
            return result
    return False

def check_ignore(rules, path):
    if os.path.isabs(path):
        raise Exception("This function requires path to be relative to the repository's root")

    result = check_ignore_scoped(rules.scoped, path)
    if result != None:
        return result

    return check_ignore_absolute(rules.absolute, path)

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

class GitObject:

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
    def init(self):
        self.kvlm = dict()

    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)

    def serialize(self, data):
        return kvlm_serializze(data)

class GitTreeLeaf:
    def __init__(self, mode, path, sha):
        self.mode = mode
        self.path = path
        self.sha = sha

class GitTree:
    fmt = b'tree'

    def __init__(self) -> None:
        self.items = []
    
    def serialize(self):
        return tree_serialize(self)
    
    def deserialize(self, data) -> None:
        self.items = tree_parse(data)

class GitTag(GitCommit):
    fmt = b'tag'

class GitIndexEntry:
    def __init__(self, ctime=None, mtime=None, dev=None, ino=None,
                 mode_type=None, mode_perms=None, uid=None, gid=None,
                 fsize=None, sha=None, flag_assume_valid=None,
                 flag_stage=None, name=None):
      # changed time for metadata => (timestamp in seconds, nanoseconds)
      self.ctime = ctime
      # modified time for file data => (timestamp in seconds, nanoseconds)
      self.mtime = mtime
      # id of device
      self.dev = dev
      # inode number
      self.ino = ino
      # obj type => b1000 (regular), b1010 (symlink), b1110 (gitlink)
      self.mode_type = mode_type
      # The object permissions
      self.mode_perms = mode_perms
      # User ID of owner
      self.uid = uid
      # Group ID of ownner
      self.gid = gid
      # Size of this object, in bytes
      self.fsize = fsize
      # The object's SHA
      self.sha = sha
      self.flag_assume_valid = flag_assume_valid
      self.flag_stage = flag_stage
      # Name of the object (full path)
      self.name = name

class GitIndex:
    version = None
    entries = []
    def __init__(self, version=2, entries=None):
        self.version = version
        
        if not entries:
            self.entries = []
        else:
            self.entries = entries

class GitIgnore:
    absolute = None
    scoped = None

    def __init__(self, absolute, scoped):
        self.absolute = absolute
        self.scoped = scoped