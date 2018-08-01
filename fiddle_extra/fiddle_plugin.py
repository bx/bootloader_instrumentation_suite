#!/usr/bin/python2
# MIT License

# Copyright (c) 2017 Rebecca ".bx" Shapiro

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from fiddle import process_args
from enum import Enum
from fiddle.config import ConfigFile
from fiddle.config import Main
from fiddle import config

_plugin_type = Enum("PluginType",
                   ["PostProcess"])    

class PluginResultFile():
    file_type = Enum("PluginFile",
                     ["target", "target_unique", "log", "config", "file_dep"])
    def __init__(self, name,
                 kind, plugin,
                 default_rel_path=None,
                 from_arg=None):
        if default_rel_path == None:
            default_rel_path = "%s-file" % name
        self.plugin = plugin
        self.name = name
        self.relative_path = default_rel_path
        self.type_enum = kind
        self.type = kind.name
        
        self.c_file = None
        self.registered = False
        self.from_arg = from_arg

    def to_kws(self):
        kws = {}
        for i in ["type", "name", "relative_path"]:
            kws[i] = getattr(self, i)
        return {self.name: kws}
    

    def register(self):
        if self.registered:
            return
        global _plugin_type
        if self.plugin.type == _plugin_type.PostProcess:
            self.registered = True
            Main._set_generic_config()


class FiddlePlugin():
    plugin_type = _plugin_type
    def __init__(self, name,
                 arg_parsers=[],
                 kind=_plugin_type.PostProcess,
                 files=[],
                 software=[],
                 supported_traces=Main.object_config_lookup("TraceMethod")):
        self.name = name
        self.parser = process_args.FiddleArgParser("F%splugin" % (self.name + " "),
                                                   True, arg_parsers)
        self.software = software
        self.supported_traces = supported_traces
        self.args = self.parser.args
        self.task_mgr = self.parser.task_manager()
        self.files = files
        self.unique = False
        if kind == PluginResultFile.file_type.target_unique:
            self.unique = True
            kind = PluginResultFile.file_type.target
        self.type = kind
        self.config_obj = None
        self._setup_config_obj()


    def _setup_config_obj(self):
        kws =  {"name": self.name, "Files": {}}
        
        for f in self.files:
            if f.from_arg:
                if f.from_arg == True:
                    n = f.name
                else:
                    n = f.from_arg
                f.relative_path = getattr(self.args, n)
            kws["Files"].update(f.to_kws())            
        if self.type == self.plugin_type.PostProcess:            
            self.config_obj = config.configtypes["PostProcess"](kws, self.name, update_raw=True)
            for i in ["software", "supported_traces"]:
                setattr(self.config_obj, i, getattr(self, i))
        if self.config_obj:
            self.config_obj.setup()
    
    def run(self, **args):
        pass

    
