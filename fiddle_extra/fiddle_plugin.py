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
import os


_plugin_type = Enum("PluginType",
                    ["PostProcess"])


class PluginResultFile():
    file_type = Enum("PluginFile",
                     ["target", "target_unique", "log",
                      "config", "file_dep"])

    def __init__(self, name,
                 kind, plugin,
                 default_rel_path=None,
                 from_arg=False,
                 shortened=None,
                 parser_kws=None,
                 stage_dependent=False):
        if default_rel_path is None:
            default_rel_path = "%s-file" % name
        self.default_rel_path = default_rel_path
        self.plugin = plugin
        self.name = name
        self.type_enum = kind
        self.type = kind.name
        global _plugin_type
        if self.plugin.type_enum is _plugin_type.PostProcess and \
           self.type_enum in [self.file_type.target,
                              self.file_type.target_unique]:
            self.stage_dependent = True
        else:
            self.stage_dependent = stage_dependent
        self.c_file = None
        self.registered = False
        self.shortened = shortened
        self.from_arg = from_arg
        self.arg_name = None
        self.parser_kws = parser_kws
        self._setup_parser_info()

    def full_path(self, stage=None):
        fs = getattr(getattr(Main.raw, self.plugin.type), self.plugin.name).Files
        raw = getattr(fs, self.name)
        if raw.stage_dependent:
            return getattr(raw, stage.stagename)
        else:
            return raw.path

    def relative_path(self, args):
        if self.from_arg:
            if self.from_arg is True:
                n = self.name
            else:
                n = self.from_arg
            return getattr(args, n)
        else:
            return self.default_rel_path

    def _setup_parser_info(self):
        if self.from_arg:
            if self.from_arg is not True:
                self.arg_name = "--" + self.from_arg
            else:
                self.arg_name = "--" + self.name

            kws = {
                "action": "store",
                "default": self.default_rel_path
            }
            if self.parser_kws is not None:
                self.parser_kws.update(kws)
            else:
                self.parser_kws = kws

    def to_obj_kws(self, args):
        kws = {}
        for i in ["type", "name", "stage_dependent"]:
            kws[i] = getattr(self, i)
        kws["relative_path"] = self.relative_path(args)
        return {self.name: kws}

    def register(self):
        if self.registered:
            return
        global _plugin_type
        if self.plugin.type_enum == _plugin_type.PostProcess:
            self.registered = True
            Main._set_generic_config()

    def parser_info(self):
        if not self.from_arg:
            raise Exception("Plugin %s file %s info is not obtained from an argument" %
                            (self.plugin.name, self.name))
        names = [] if not self.shortened else [self.shortened]
        names.append(self.arg_name)
        return (names, self.parser_kws)


class FiddlePlugin():
    plugin_type = _plugin_type

    def __init__(self, name,
                 arg_parsers=[],
                 kind=_plugin_type.PostProcess,
                 files=[],
                 software=[],
                 supported_traces=Main.object_config_lookup("TraceMethod")):
        self.name = name
        if kind == PluginResultFile.file_type.target_unique:
            self.unique = True
            kind = PluginResultFile.file_type.target
        self.type_enum = kind
        self.type = kind.name
        self.software = software
        self.supported_traces = supported_traces
        self.args = None
        self.files = {f.name: f for f in files}
        self.unique = False
        self.config_obj = None
        self.parser = None
        self.task_mgr = None
        self.arg_parsers = arg_parsers

    def setup(self):
        file_args = map(lambda x: x.parser_info(),
                        filter(lambda x: x.from_arg,
                               self.files.itervalues()))
        self.arg_parsers.extend(file_args)

        self.parser = process_args.FiddleArgParser("F%splugin" %
                                                   (self.name + " "),
                                                   self,
                                                   self.arg_parsers)
        self.args = self.parser.args
        self.task_mgr = self.parser.task_manager()
        if self.type_enum is self.plugin_type.PostProcess:
            self.task_mgr.postprocess_trace()
        else:
            raise Exception("unsupported plugin type %s" % self.type)

    def add_files(self, files):
        self.files.update({f.name: f for f in files})

    def get_file_path(self, filename, stage=None):
        return self.files[filename].full_path(stage)

    def get_setup_tasks(self, mgr):
        tasks = []
        d = Main.raw.runtime.trace.data_dir
        dstdir = os.path.join(d, "plugin_data", self.name)
        tasks.append(mgr._mkdir(dstdir))
        tasks.extend(mgr.import_files(self.config_obj,
                                      getattr(Main.raw.PostProcess,
                                              self.name),
                                      dstdir,
                                      output_files=True))
        return tasks

    def setup_config_obj(self):
        kws = {"name": self.name, "Files": {}}
        for f in self.files.itervalues():
            kws["Files"].update(f.to_obj_kws(self.args))
        if self.type_enum == self.plugin_type.PostProcess:
            self.config_obj = config.configtypes["PostProcess"](kws,
                                                                self.name)
            for i in ["software", "supported_traces"]:
                setattr(self.config_obj, i, getattr(self, i))
        if self.config_obj:
            self.config_obj.setup()

    def __call__(self, **args):
        self.run(**args)

    def run(self, **args):
        pass
