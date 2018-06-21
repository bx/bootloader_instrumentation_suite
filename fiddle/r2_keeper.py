import r2pipe
import json

files = {}
entry = {}
    

def gets(f, cmd):
    if f in files.keys():
        handle = files[f]
    else:
        handle = r2pipe.open(f, ['-2'])
        files[f] = handle
        #handle.cmd('e asm.assembler=arm.gnu')
        
        entry[f] = handle.cmd("s")
        handle.cmd('e anal.bb.maxsize=10000')
        handle.cmd('aas')
        #handle.cmd('e asm.assembler=arm.gnu')
        #handle.cmd('e asm.arch=arm.gnu')
        
    out = handle.cmd(cmd)
    return out

def get(f, cmd):
    out = gets(f, cmd)
    try:        
        return json.loads(out)
    except ValueError:
        return {}

def entrypoint(f):
    return entry[f]
    
def cd(f, dst):
    gets(f, "cd %s" % dst)
