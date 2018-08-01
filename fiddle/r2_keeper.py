import r2pipe
import json

files = {}
entry = {}
bba = []

def gets(f, cmd):
    if f in files.keys():
        handle = files[f]
    else:
        handle = r2pipe.open(f, ['-2'])
        files[f] = handle
        entry[f] = handle.cmd("s")
        handle.cmd('e anal.bb.maxsize=10000')
        handle.cmd('aac*')

    out = handle.cmd(cmd)
    return out


def run_aab(f):    
    if f in bba:
        return
    else:
        gets(f, "aab") # run basic block analysis
        bba.append(f)
    return

def get(f, cmd):
    out = gets(f, cmd)
    try:
        return json.loads(out)
    except ValueError:
        return []


def entrypoint(f):
    return entry[f]


def cd(f, dst):
    gets(f, "cd %s" % dst)
