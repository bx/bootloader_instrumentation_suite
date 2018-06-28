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
import traceback
import os
import re
import sys
import toml
import git_mgr
import run_cmd
import pure_utils
import intervaltree
from munch import munchify, Munch


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr

import collections

configtypes = {}
registry = {}
defaults = {}

class ConfigException(Exception):
    pass

def _merge_into_munch(to, fro):
    for (k, v) in fro.iteritems():
        if not hasattr(to, k):
            # add placeholder
            setattr(to, k, Munch())
        if isinstance(v, collections.Mapping):
            setattr(to, k,  _merge_into_munch(to.get(k, Munch()), v))
        else:
            setattr(to, k, v)
    return to

def _raw_field_name(obj, attr):
    if obj is None:
        return attr
    classname = obj.__class__.__name__
    name = ""
    if (not classname in ["Main", "Target"]) and hasattr(obj, "name"):
        name = obj.name + "."
    return "%s.%s%s" % (classname, name, attr)

def _get_raw_config(obj, attr):
    b = Main.raw
    if not b:
        b = Main.default_raw
    attr = _raw_field_name(obj, attr)
    return b.get(attr)



def _update_raw_config(obj, attr, value):
    b = Main.raw
    if not b:
        b = Main.default_raw
    attr = _raw_field_name(obj, attr)
    def _dotted_str_to_dict(s, d):
        dot = s.rfind(".")
        if dot < 0:
            return {str(s): d}
        else:
            (substr, value) = s.rsplit(".", 1)
            return _dotted_str_to_dict(str(substr), {str(value): d})
    new = _dotted_str_to_dict(attr, value)
    _merge_into_munch(b, new)


class SpecialConfig(object):
    def _update_raw(self, attr, value):
        name = ""
        if self.name:
            name = "%s." % self.name
        self.software._update_raw("%s.%s%s" %
                                  (self.typ,
                                   name, attr),
                                  value)

    def __getattr__(self, field):
        special = SpecialConfig.special_fields
        if name in special:
            val = super(type(self), self).__getattribute__(self._gettr_name(field))
            if self._gettr_name(field, True):
                return val
            else:
                val = self.software.populate_path(val)
                setattr(self._gettr_name(field),
                        val)
                setattr(self._gettr_name(field, True),
                        True)
                return val
        else:
            return super(type(self), self).__getattribute__(field)


    def __setattr__(self, field, value):
        special = SpecialConfig.special_fields
        if field in special:
            self.__dict__[self._gettr_name(field)] = value
            self.__dict__[self._gettr_name(field, True)] = None
        else:
            self.__dict__[field] = value

    def _gettr_name(self, n, checked=False):
        if checked:
            n = n + "_checked"
        return "_" + n

    def setfield(self, n, default=None):
        v = getattr(self, n, default)
        if n not in SpecialConfig.special_fields:
            setattr(self, n, v)
            self._update_raw(n, v)
        else:
            setattr(self, self._gettr_name(n), v)
            setattr(self, self._gettr_name(n, True),
                    v)
            self._update_raw(n, v)


    def __init__(self, name, info, software, typ):
        try:
            f = SpecialConfig.special_fields
        except AttributeError:
            SpecialConfig.special_fields = []
        self.typ = typ
        self.name = name
        self.software = software

        for (k, v) in info.iteritems():
            setattr(self, k, v)
            self._update_raw(k, v)



class ConfigFile(SpecialConfig):
    special_fields = ["path", "command", "cached_path", "file_deps"]
    supported_types = ["default", "log", "config", "target", "mmap", "file_dep", "image"]
    def __init__(self, name, info, software):
        SpecialConfig.__init__(self, name, info, software, "Files")
        self.setfield("type", "default")
        self.setfield("subtype", "")
        self.setfield("cache", True)
        generated = getattr(info, "generate", False) or "generator" in info.keys() \
                    or "command" in info.keys() or self.type in ["log", "target", "image"]
        self.setfield("generate", generated)
        self.setfield("imported", False)
        self.setfield("file_deps", [])
        if not (self.generate or hasattr(self, "path")):
            raise ConfigException("Non-generated file %s (%s) needs a  path definition"
                                  % (name, software.name))

        if not hasattr(self, "relative_path") and not hasattr(self, "path"):
            self.setfield("relative_path", name)


        if not self.type in self.supported_types:
            raise ConfigException("File %s (%s) has unknown type '%s', should be one of %s"
                                  % (name, software.name, self.type, self.supported_types))

class Reloc(SpecialConfig):
    def __init__(self, name, info, stage):
        SpecialConfig.__init__(self, name, info,
                               stage,
                               "Reloc")
        self.stage = stage


class Longwrite(SpecialConfig):
    def __init__(self, name, info, stage):
        SpecialConfig.__init__(self, name, info,
                               stage,
                               "Longwrite")
        self.stage = stage


class ExecConfig(SpecialConfig):
    special_fields = ["command", "commands"]
    def __init__(self, cfgs, software, kind):
        if not "commands" in cfgs.keys():
            cfgs["commands"] = []
        SpecialConfig.__init__(self, "", cfgs, software, kind)
        self.kind = kind
        self.software = software


class ConfigTypeRegistrar(type):
    def __new__(cls, clsname, bases, attrs):
        newcls = type.__new__(cls, clsname, bases, attrs)
        global configtypes
        if clsname not in configtypes.keys():
            configtypes[clsname] = newcls
        return newcls


class ConfigObject(object):
    __metaclass__ = ConfigTypeRegistrar

    def setup(self):
        pass

    def __init__(self, kw, name=None, default=False):
        self.default = default
        v = None
        if name is not None:
            self.name = name
        else:
            self.name = ""
            if "name" in kw.keys():
                self.name = kw["name"]
                del kw["name"]
                if "name" in self.required_fields:
                    self.required_fields.remove("name")
        self._update_raw("name", self.name)
        fields = kw.keys()

        for f in self.required_fields:
            if f not in fields:
                default_location = getattr(Main.default_raw, self.__class__.__name__)
                v = getattr(default_location, f, None)
                if v is None:
                    raise ConfigException("Missing field '%s' in "
                                          "configuration %s" % (f, self.__class__.__name__))
                kw[f] = v
        self._files = {}
        self._configs = []
        self._GDB_configs = []
        for (k, v) in kw.iteritems():
            if k == "Files":
                for (name, info) in v.iteritems():
                    if name in self._files.keys():
                        raise ConfigException("A there is already a file named '%s' in the configuration for software '%s'" % (name, self.name))
                    self._files[name] = ConfigFile(name, info, self)
            elif k == "ExecConfig":
                self._configs.append(ExecConfig(v, self, "exec"))
            elif k == "GDBConfig":
                self._GDB_configs.append(ExecConfig(v, self, "gdb"))
            else:
                setattr(self, k, v)
                self._update_raw(k, v)
        cls = self.__class__.__name__
        global registry
        global defaults
        if self.default:
            if cls not in defaults:
                defaults[cls] = []
            defaults[cls].append(self)
        else:
            if cls not in registry.keys():
                registry[cls] = []
            registry[cls].append(self)
        self.shell = run_cmd.Cmd()

    def _update_raw(self, attr, value):
        _update_raw_config(self, attr, value)

    def _get_raw(self, attr):
        return _get_raw_config(self, attr)


    @classmethod
    def _do_format(cls, item, kws, recurse=10):
        # check for accidental double dots
        ls = "[a-zA-Z0-9_-]"
        dd = "[{](?:%s+[.])*[.]+(?:[.]|%s)*[}]" % (ls, ls)
        if re.search(dd, item):
            return ConfigException("cannot have double dots in value's format specifier '%s'\n" %
                                   item)

        final = None
        if recurse < 0:
            return item
        do_again = False
        final = item
        # print "--formatting %s, %s, %s" % (item, recurse, recurse < 0)

        def eval_format(s):
            try:
                return s.format(**kws)
            except AttributeError as e:
                # print "Exception (%s,%s) formatting %s, %s, %s" % (e, e.args, item,
                #                                                    recurse, recurse < 0)
                return e

        if (not isinstance(item, basestring) and isinstance(item, list)):
            final = [eval_format(i) for i in item]
            do_again = any(lambda x: "}" in x and "{" in x and length(x) > 2, final)
        else:
            final = eval_format(item)
            do_again = isinstance(final, str) and "}" in final and "{" in final and len(final) > 2
        do_again = do_again and (not item == final)
        # print "%s,%s -> %s" % (do_again, item, final)
        if do_again:
            return cls._do_format(final, kws, recurse - 1)
        else:
            return final

    def populate_path_from_name(self, name, or_default=False, optional=True, do_setattr=False):
        if or_default:
            v = self.value_or_default(name)
        else:
            if optional and not hasattr(self, name):
                return None
            v = getattr(self, name)
        if (not optional) and v is None:
            raise ConfigException("Required path '%s' in '%s' not defined" %
                                  (name, self.__class__.__name__))
        elif v is None:
            return None
        else:
            # print "populate %s" % v
            v = self.populate_path(v)

        if do_setattr:
            setattr(self, name, v)
            self._update_raw(name, v)
        return v

    def populate_path(self, path, isroot=False):
        def _pop(i):
            i = self._populate_from_config(i)
            i = os.path.expanduser(i)
            return i
        if (not isinstance(path, basestring) and isinstance(path, list)):
            path = map(_pop, path)
        else:
            path = _pop(path)
        return path

    def _populate_from_config(self, s, use_default=True):
        if self.default:
            return s
        else:
            return Main.populate_from_config(s, use_default, is_default=self.default)

    def _set_populate_config(self, name):
        if hasattr(self, name):
            item = getattr(self, name)
            if (not isinstance(item, basestring) and isinstance(item, list)):
                item = [self._populate_from_config(i) for i in item]
            else:
                item = self._populate_from_config(item)
            self._update_raw(name, item)
            setattr(self, name, item)

    def config_class_lookup(self, classname):
        global registry
        global defaults
        if self.default:
            d = defaults
        else:
            d = registry
        try:
            regentry = d[classname]
        except KeyError:
            d[classname] = []
            return []
        return regentry

    def object_config_lookup(self, classname, name=None):
        regentry = self.config_class_lookup(classname)
        if name is None:
            return regentry
        matches = [i for i in regentry if i.name == name]

        if len(matches) == 0:
            raise ConfigException("no %s named %s found" % (classname, name))
        elif len(matches) > 1:
            raise ConfigException("more than one %s named %s found" % (classname, name))
        else:
            return matches[0]

    def attr_exists(self, attr):
        try:
            a = getattr(self, attr)
            if a is not None:
                return True
            else:
                return False
        except AttributeError:
            return False

    def value_or_default(self, attr, set_attr=False):
        if self.default:
            return getattr(self, attr)
        if attr in dir(self):
            val =  getattr(self, attr)
            val = Main.populate_from_config(val, is_default=self.default)
        else:
            default_name = ""
            if self.__class__.__name__ not in ["Target", "Main"]:
                global defaults
                default_name = defaults[self.__class__.__name__][0].name + "."

            val = self._populate_from_config("{%s.%s%s}" %
                                             (self.__class__.__name__, default_name, attr))
        if set_attr:
            setattr(self, attr, val)
            self._update_raw(attr, val)
        return val

    def _check_path(self, which, name="",
                    message="Path for '{}' at '{}' does not exist", in_use=False):
        if self.default:
            return
        if not name:
            name = "%s.%s" % (self.__class__.__name__, which)
        path = getattr(self, which, None)
        if not self.default and path and (not os.path.exists(path)):
            raise ConfigException(message.format(name, path))


class Main(ConfigObject):
    required_fields = ["name"]
    shell = run_cmd.Cmd()

    test_suite_dir = os.path.realpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)), ".."))
    configs = {}
    supported_tracing_methods = set()
    cc = ""
    runtime = {}
    verbose = False

    def __init__(self, kw, name=None, default=False):
        self.default = default
        self._target = None
        self._target_checked = None
        self._target_software = None
        self._target_software_checked = None
        self._target = None
        self._target_checked = None
        self._stages = None
        self._stages_checked = None
        self._traces = None

        self.test_suite_path = Main.test_suite_dir
        self._update_raw("test_suite_path", self.test_suite_path)
        super(Main, self).__init__(kw, name, default)

        self.root = self.populate_path(self.root, isroot=True)
        self._check_path("root")
        self._update_raw("root", self.root)

        self.hw_info_path = self.populate_path_from_name("hw_info_path", True)
        self._check_path("hw_info_path")
        self._update_raw("hw_info_path", self.hw_info_path)
        self.cc = self.populate_path_from_name("cc", or_default=True)
        self.cc = os.path.expanduser(self.cc)
        if not os.path.exists(self.cc + "gcc"):
            raise ConfigException("There does not appear to be a gcc compiler (Main.cc) at %sgcc"
                                  % Main.cc)
        self._update_raw("cc", self.cc)
        self.test_data_path = self.populate_path(self.test_data_path)
        self._update_raw("test_data_path", self.test_data_path)

    def setup(self):
        if self.attr_exists("setup_done"):
            return
        self.setup_done = True

    @classmethod
    def populate_from_config(cls, value, use_default=True, is_default=False):
        if (not isinstance(value, str)) or (not (("{" in value) and ("}" in value)) or
                                            (len(value) < 3)):
            return value
        if not cls.raw:
            is_default = True
        if is_default:
            return value
        else:
            r = cls._do_format(value, cls.raw)
            if isinstance(r, Exception):
                if use_default:
                    r2 = cls._do_format(value, cls.default_raw)
                    if isinstance(r2, Exception):
                        raise ConfigException("Unable to lookup template name '%s' in %s of config file (also: %s: %s)" % (r.args, value, r2.message, r2.args))
                    else:
                        r = r2
            return r

    @classmethod
    def set_config(cls, key, value):
        cls.configs[key] = value

    @classmethod
    def has_config(cls, key, *args):
        try:
            cls.get_config(cls, key, *args)
            return True
        except KeyError:
            return False

    @classmethod
    def get_config(cls, key, *args):
        if key in cls.configs.iterkeys():
            v = cls.configs[key]
            if callable(v):
                return v(*args)
            else:
                return v
        else:
            raise KeyError("Config value %s not set" % key)

    def _get_generic_config(self, name, key, stage="", catch_except=False):
        if not stage:
            s = ""
        elif type(stage) == str:
            s = stage
        else:
            s = stage.stagename
        o = Main.raw
        if name:
            o = getattr(o, name)
        attrs = key.split(".")
        for a in attrs:
            o = getattr(o, a)
        if s:
            o = getattr(o, s)
        return o

    def _set_generic_config(self, name, key, value, stage=""):
        if not stage:
            s = ""
        elif type(stage) == str:
            s = stage
        else:
            s = stage.stagename
        key = "%s.%s" % (name, key)
        if stage:
            key += ".%s" % s
        self._update_raw(key, value)

    def set_runtime_config(self, key, value, stage=None, catch_except=False):
        self._set_generic_config("runtime", key, value, stage)

    def get_runtime_config(self, key, stage=None, catch_except=False):
        return self._get_generic_config("runtime", key, stage)

    def get_policy_config(self, key, stage=None, catch_except=False):
        return self._get_generic_config("policies", key, stage, catch_except)

    def get_target_config(self,  key="", stage=None, catch_except=False):
        return self._get_generic_config("runtime", "target."+key, stage, catch_except)

    def get_static_analysis_config(self, key="", stage=None, catch_except=False):
        return self._get_generic_config("static_analysis", key, stage, catch_except)

    def stage_from_name(self, stagename):
        s = None
        for stage in self.object_config_lookup("TargetStage"):
            if stage.stagename == stagename:
                s = stage
                break
        return s

    @property
    def traces(self):
        if not self._traces:
            self._traces = self.object_config_lookup("TraceMethod")
        return self._traces

    @property
    def postprocesses(self):
        if not self._pps:
            self._pps = self.object_config_lookup("PostProcess")
        return self._pps

    @property
    def stages(self):
        if not self._stages:
            self._stages = self.object_config_lookup("TargetStage")
            if 0 == len(self._stages):
                self._stages = defaults["TargetStage"]

        return self._stages

    @property
    def target_software(self):
        if not self._target_software:
            target_software_name = self.target.software
            if isinstance(target_software_name, str):
                self._target_software = self.object_config_lookup("Software", target_software_name)
            else:
                self._target_software = target_software_name
        return self._target_software

    @property
    def target(self):
        if not self._target:
            for s in self.object_config_lookup("Target"):
                self._target = s
                break
        return self._target

    def get_hardwareclass_config(self):
        return self.object_config_lookup("HardwareClass", Main.hardwareclass)


class HardwareClass(ConfigObject):
    required_fields = ["hosts"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.populate_path_from_name("hw_info_path", or_default=True, do_setattr=True)
            self._check_path("hw_info_path")
            self._update_raw("hw_info_path", self.hw_info_path)

            self.setup_done = True
            self.host_cfgs = {}
            for h in self.hosts:
                self.host_cfgs[h] = self.object_config_lookup("HostConfig", h)

            if not self.attr_exists("addr_range"):
                self.addr_range = Main.default_raw.HardwareClass._hw.addr_range
            lo = long(self.addr_range[0])
            hi = long(self.addr_range[1])
            self.addr_range = intervaltree.IntervalTree(
                [intervaltree.Interval(lo, hi)]
            )
            range_intervals = []
            self.addr_range_names = []
            if self.attr_exists("named_addr_ranges"):
                for (k,[lo, hi]) in self.named_addr_ranges.iteritems():
                    self.addr_range_names.append(k)
                    inter = intervaltree.Interval(long(lo),
                                                  long(hi))
                    range_intervals.append(inter)
                    setattr(self, k, inter)
                    self._update_raw(k, inter)

            self.ram_ranges = intervaltree.IntervalTree(range_intervals)
            self.ram_ranges.merge_overlaps()
            self.non_ram_ranges = self.addr_range
            for r in self.ram_ranges:
                self.non_ram_ranges.chop(r.begin, r.end)
                self.non_ram_ranges.remove_overlap(r)
            if not hasattr(self, "default_host"):
                self.default_host = self.hosts[0]


class HostConfig(ConfigObject):
    required_fields = ["tracing_methods"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.setup_done = True
            trace_names = self.tracing_methods
            self.tracing_methods = []
            k = "TraceMethod"
            global registry
            if not self.default:
                lookup = registry[k]
                for t in trace_names:
                    if not any([t == i.name for i in lookup]):
                        global defaults
                        match = [i for i in defaults[k] if t == i.name]
                        registry[k].extend(match)
                        for m in match:
                            m.default = False
                            _merge_into_munch(Main.raw, {"TraceMethod":
                                                         {m.name:
                                                          getattr(Main.default_raw.TraceMethod,
                                                                  m.name)}})
            for t in trace_names:
                self.tracing_methods.append(self.object_config_lookup(k, t))
            Main.supported_tracing_methods.update(self.tracing_methods)
            if not self.attr_exists("host_software"):
                self.host_software = None
            if not self.attr_exists("is_baremetal"):
                self.is_baremetal = False
            if not self.attr_exists("default_tracing"):
                self.default_tracing = [trace_names[0]]


class TraceMethod(ConfigObject):
    required_fields = []

    def setup(self):
        if not self.attr_exists("setup_done"):
            if not self.attr_exists("software"):
                self.software = []
            else:
                ss = self.software
                self.software = [self.object_config_lookup("Software", s) for s in ss]
            self.setup_done = True
            if not self.attr_exists("run"):
                self.run = Main.raw.TraceMethod.run


class PostProcess(ConfigObject):
    required_fields = []

    def setup(self):
        if not self.attr_exists("setup_done"):
            if not self.attr_exists("software"):
                self.software = []
            else:
                ss = self.software
                self.software = [self.object_config_lookup("Software", s) for s in ss]
            self.setup_done = True

            if not self.attr_exists("supported_traces"):
                self.supported_traces = []


class Software(ConfigObject):
    required_fields = ["root"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.manager = None
            self.setup_done = True
            self.root = self.populate_path_from_name("root", False, False, True)
            self._update_raw("root", self.root)
            if os.path.isdir(os.path.join(self.root, ".git")):
                self.git = git_mgr.GitManager(self.root)
            else:
                self.git = None
            map(lambda x: self.value_or_default(x, True),
                ["build"])
            if self.build:
                map(lambda x: self.value_or_default(x, True),
                    ["compiler", "build_prepare", "build_cmd", "clean"])

            self.basename = self.name
            self.populate_path_from_name("compiler", optional=True, do_setattr=True)
            if not self._files:
                self._update_raw("Files", {})


class Target(ConfigObject):
    required_fields = ["software"]

    def setup(self):
        self.name = self.software
        # lookup stage objects
        if not self.attr_exists("setup_done"):
            self.setup_done = True
            self.stages = self.object_config_lookup("TargetStage")

            if self.attr_exists("default_stages"):
                Main.default_stages = [Main.stage_from_name(s) for s in self.default_stages]
            else:
                if len(self.stages) > 0:
                    Main.default_stages = [self.stages[0]]
                else:
                    Main.default_stages = Main.stages


class TargetStage(ConfigObject):
    required_fields = ["elf"]

    def __init__(self, kw, name=None, default=False):
        self.reloc_descrs = []
        self.longwrites = []
        d = kw.iteritems()
        super(TargetStage, self).__init__(kw, name, default)
        todel = []
        self.stagename = self.name
        for (k, v) in d:
            if k == "Reloc":
                for (name, desc) in v.iteritems():
                    self.reloc_descrs.append(Reloc(name, desc, self))
                todel.append(k)
            elif k == "Longwrite":
                for (name, desc) in v.iteritems():
                    self.longwrites.append(Longwrite(name, desc, self))
                todel.append(k)

        for k in todel:
            del kw[k]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.setup_done = True
            self.stagename = self.name
            self.post_build_setup_done = False

            ints = ["minpc",
                    "maxpc",
                    "exitpc",
                    "entrypoint",
                    "image_size"]
            map(lambda x: self.value_or_default(x, True),
                ints)
            for i in ints:
                val = getattr(self, i)
                if type(val) == str:
                    try:
                        val = int(val)
                    except ValueError:
                        continue
                    setattr(self, i, val)
                    self._update_raw(i, val)

            self.target_cfg = Main.target_software
            self.elf = self._populate_from_config(self.elf)
            self.elfname = os.path.basename(self.elf)
            if not hasattr(self, "image"):
                self.image = self.elf
            else:
                self.image = self._populate_from_config(self.image)

    def post_build_setup(self, root):
        if not self.post_build_setup_done:
            self.post_build_setup_done = True

            image = os.path.join(root, self.image)
            elf = os.path.join(root, self.elf)

            (lo, hi) = pure_utils.get_min_max_pcs(elf)
            if self.minpc < 0:
                self.minpc = lo
            if self.maxpc < 0:
                self.maxpc = hi
            if self.entrypoint < 0:
                self.entrypoint = pure_utils.get_entrypoint(elf)
            if self.image_size < 0:
                self.image_size = pure_utils.get_image_size(self.image)
            if type(self.exitpc) == str:
                stage = self.object_config_lookup("TargetStage", self.exitpc)
                if not stage.post_build_setup_done:
                    stage.post_build_setup(root)
                self.exitpc = stage.entrypoint


# override int parser so it also parses hex
def hexint(s, t):
    r'[-]?(0[xX][0-9a-fA-F]+|\d)([uU]|[lL]|[uU][lL]|[lL][uU])?'
    t.value = int(t.value, 0)
    return t


toml.TomlLexer.t_INTEGER = hexint
toml.lexer = toml.lexer = toml.TomlLexer()


cfg = "I_CONF"
if cfg not in os.environ.keys():
    config = os.path.join(os.path.expanduser("~"), ".fiddle.cfg")
    if not os.path.exists(config):
        oldconfig = config
        path = os.path.dirname(os.path.realpath(__file__))
        path = os.path.realpath(os.path.join(path, ".."))
        config = os.path.join(path, "fiddle.cfg")
else:
    config = os.path.realpath(os.environ[cfg])

if not os.path.exists(config):
    raise ConfigException("No fiddle config file found at %s." % (config))


def setup_special_fields(bunched):
    specials = {
        "Main": {"test_suite_dir": Main.test_suite_dir,
                 "test_suite_path": Main.test_suite_dir,
        },
        "config": config,
    }
    specials.update({k: "{runtime.%s}" % k for k in ["current_stage", "instance_root", "trace_root", "policy_name", "host_name", "trace_name"]})
    if 'HardwareClass' in bunched.keys():
        specials["HardwareClass"] = {}
        for name in bunched.HardwareClass.keys():
            specials["HardwareClass"]["%s" % name] = {"name": name}
    _merge_into_munch(bunched, specials)


defcfg = os.path.join(Main.test_suite_dir, 'fiddle', 'configs', "defaults.cfg")
Main.raw = {}
Main.default_raw = {}
with open(defcfg, 'r') as f:
    default_settings = toml.loads(f.read())

Main.default_raw = munchify(default_settings)
setup_special_fields(Main.default_raw)

# initialize config in this order
default_objs = []
default_objs.append(configtypes["Main"](default_settings["Main"], default=True))
default_objs.append(configtypes["Target"](default_settings["Target"], "target", default=True))
order = ["Software", "TraceMethod",  "HardwareClass", "HostConfig", "TargetStage", "PostProcess"]

for i in order:
    for (name, v) in default_settings[i].iteritems():
        if not (i == "TraceMethod" and name == "run"):
            default_objs.append(configtypes[i](v, name, default=True))

with open(config, 'r') as f:
    settings = toml.loads(f.read())


Main.raw = munchify(settings)
setup_special_fields(Main.raw)
configtypes["Main"](settings["Main"])
configtypes["Target"](settings["Target"], "target")

for i in order:
    if i in settings.keys():
        for (name, v) in settings[i].iteritems():
            if not (i == "TraceMethod" and name == "run"):
                configtypes[i](v, name)

for (k, v) in settings.iteritems():
    if k not in configtypes.keys():
        raise ConfigException("%s is not a valid config section group name" % k)


if "Main" not in registry.keys():
    raise ConfigException("We are missing 'Main' configuration data")


globals()["Main"] = registry["Main"][0]
Main.config = config

# first setup main, then targets, then everything else
Main.setup()
for (k, v) in configtypes.iteritems():
    used_defaults = []
    if k not in registry.keys():
        if k == "ConfigObject":
            continue
        registry[k] = defaults[k]
        if k == "Target":
            registry[k].setup()
        else:
            # to be initialized after Target
            used_defaults.append(registry[k])
        for l in defaults[k]:
            l.default = False
            _merge_into_munch(Main.raw, {k:
                                         {l.name: getattr(getattr(Main.default_raw, k), l.name)}})
    if hasattr(Main.raw, "TraceMethod") and not hasattr(Main.raw.TraceMethod, "run"):
        if hasattr(Main.default_raw, "TraceMethod") and hasattr(Main.default_raw.TraceMethod, "run"):
            Main.raw.TraceMethod.run = Main.default_raw.TraceMethod.run

    # merge all default software
    default_software = defaults["Software"]
    for s in default_software:
        if s.name not in [a.name for a in registry["Software"]]:
            registry["Software"].append(s)
            s.default = False
            _merge_into_munch(Main.raw, {"Software":
                                         {s.name:
                                          getattr(Main.default_raw.Software, s.name)}})

items = registry.items()
for (k, v) in items:
    if k == "Target":
        globals()[k] = v
        for instance in v:
            instance.setup()
items = registry.items()
for (k, v) in items:
    if not k == "Main" or k == "Target":
        globals()[k] = v
        for instance in v:
            instance.setup()


def _u(attr, val):
    return _update_raw_config(None, attr, val)


Main._plain_update_raw = _u
