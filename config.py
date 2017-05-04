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

import os
import yaml
import git_mgr
import run_cmd
import pure_utils
import intervaltree
configtypes = {}
registry = {}


class ConfigTypeRegistrar(type):
    def __new__(cls, clsname, bases, attrs):
        newcls = type.__new__(cls, clsname, bases, attrs)
        global configtypes
        if clsname not in configtypes.keys():
            configtypes[clsname] = newcls
        return newcls


class ConfigObject(object):
    __metaclass__ = ConfigTypeRegistrar

    def __init__(self, kw):
        fields = kw.keys()
        for f in self.required_fields:
            if f not in fields:
                raise Exception("Missing field '%s' in "
                                "configuration %s" % (f, str(self.__class__)))
        global registry

        for (k, v) in kw.iteritems():
            setattr(self, k, v)
        cls = str(self.__class__.__name__)

        if cls not in registry.keys():
            registry[cls] = []
        registry[cls].append(self)
        self.shell = run_cmd.Cmd()

    def config_class_lookup(self, classname):
        global registry

        try:
            regentry = registry[classname]
        except KeyError:
            raise Exception("%s config does not exist" % classname)
        return regentry

    def object_config_lookup(self, classname, name):
        regentry = self.config_class_lookup(classname)
        matches = [i for i in regentry if i.name == name]
        if len(matches) == 0:
            raise Exception("no %s named %s found" % (classname, name))
        elif len(matches) > 1:
            raise Exception("more than one %s named %s found" % (classname, name))
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

    def set_default(self, attr, value):
        if not self.attr_exists(attr):
            setattr(self, attr, value)

    def setup(self):
        pass


class Main(ConfigObject):
    required_fields = ["root", "cc", "test_data_path", "python", "bootloader",
                       "test_suite_path", "hw_info_path", "task_handlers"]
    shell = run_cmd.Cmd()
    hardware_instances = {}

    test_suite_dir = os.path.dirname(os.path.realpath(__file__))
    configs = {}
    supported_tracing_methods = set()

    @classmethod
    def set_config(cls, key, value):
        cls.configs[key] = value

    @classmethod
    def get_config(cls, key, *args):
        if key in cls.configs.iterkeys():
            v = cls.configs[key]
            if callable(v):
                return v(*args)
            else:
                return v
        else:
            return None

    def stage_from_name(self, stagename):
        s = None
        for stage in self.get_bootloader_cfg().supported_stages.itervalues():
            if stage.stagename == stagename:
                s = stage
                break
        return s

    def hw_from_name(self, tracename):
        hw = None
        for h in self.hardware_instances.itervalues():
            if h.tracename == tracename:
                hw = h
                break
        return hw

    def get_bootloader_cfg(self):
        return self.object_config_lookup("Bootloader", self.bootloader)

    def get_bootloader_root(self):
        return self.get_bootloader_cfg().software_cfg.root

    def get_hardwareclass_config(self):
        return self.object_config_lookup("HardwareClass", self.hardwareclass)

    @property
    def test_suite_path(self):
        return os.path.join(self.root, self.__ts_path)

    @test_suite_path.setter
    def test_suite_path(self, ts_path):
        self.__ts_path = ts_path

    @property
    def test_data_path(self):
        return os.path.join(self.root, self.__td_path)

    @test_data_path.setter
    def test_data_path(self, td_path):
        self.__td_path = td_path

    @property
    def hw_info_path(self):
        return os.path.join(self.root, self.__hw_path)

    @hw_info_path.setter
    def hw_info_path(self, hw_path):
        self.__hw_path = hw_path


class JtagConfig(ConfigObject):
    required_fields = ["name", "cfg_path"]

    def setup(self):
        if not hasattr(self, "init_commands"):
            self.init_commands = []


class HardwareClass(ConfigObject):
    required_fields = ["name", "sdskeleton", "types", "supported_bootloaders",
                       "phy_addr_range", "base_mem_map", "tech_reference"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.setup_done = True

            self.supported_bootloader_cfgs = {}
            self.hardware_type_cfgs = {}
            for b in self.supported_bootloaders:
                self.supported_bootloader_cfgs[b] = self.object_config_lookup("Bootloader", b)

            for h in self.types:
                self.hardware_type_cfgs[h] = self.object_config_lookup("HardwareConfig", h)
            self.base_mem_map = os.path.join(Main.hw_info_path, self.name, self.base_mem_map)
            self.sdskeleton = os.path.join(Main.hw_info_path, self.name, self.sdskeleton)
            self.tech_reference = os.path.join(Main.hw_info_path, self.name, self.tech_reference)

            if self.attr_exists("phy_addr_range"):
                lo = self.phy_addr_range['loaddr']
                hi = self.phy_addr_range['hiaddr']
                self.phy_addr_range = intervaltree.IntervalTree(
                    [intervaltree.Interval(lo, hi)]
                )
            range_intervals = []
            if self.attr_exists("ram_ranges"):
                self.ram_range_names = [r['name'] for r in self.ram_ranges]
                for r in self.ram_ranges:
                    lo = r['loaddr']
                    hi = r['hiaddr']
                    inter = intervaltree.Interval(lo, hi)
                    range_intervals.append(inter)
                    setattr(self, r['name'], inter)
            else:
                self.ram_range_names = []
            self.ram_ranges = intervaltree.IntervalTree(range_intervals)
            self.ram_ranges.merge_overlaps()
            self.non_ram_ranges = self.phy_addr_range
            for r in self.ram_ranges:
                self.non_ram_ranges.chop(r.begin, r.end)
                self.non_ram_ranges.remove_overlap(r)


class HardwareConfig(ConfigObject):
    required_fields = ["name", "task_handler", "host_software", "tracing_methods"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.setup_done = True
            if self.attr_exists("default_jtag"):
                jtag = self.default_jtag
                self.jtag_cfg = self.object_config_lookup("JtagConfig", jtag)
            Main.supported_tracing_methods.update(self.tracing_methods)


class Software(ConfigObject):
    required_fields = ["name", "root"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.manager = None
            self.setup_done = True
            if self.attr_exists("path") and (self.path == "cc"):
                self.root = Main.cc
            elif not (self.attr_exists("path") and self.path == "full"):
                self.root = os.path.join(Main.root, self.root)
            else:
                # self.root is full path
                pass
            if self.attr_exists("general"):
                self.general = self.general
            else:
                self.general = False
            self.set_default("build", None)
            # global buildregistry
            # if self.attr_exists("build"):
            #    self.build = buildregistry[self.build](self)
            if os.path.isdir(os.path.join(self.root, ".git")):
                self.git = git_mgr.GitManager(self.root)
            else:
                self.git = None
            if self.attr_exists("compiler"):
                self.compiler_cfg = self.object_config_lookup("Software", self.compiler)
            #if self.attr_exists("binary"):
            #    self.binary = self.root + self.binary
            self.root = os.path.join(Main.root, self.root)

    def register_manager(self, mgr):
        self.manager = mgr


class Bootloader(ConfigObject):
    required_fields = ["name", "arch", "stages", "software"]

    def setup(self):
        # lookup stage objects
        if not self.attr_exists("setup_done"):
            self.setup_done = True
            self.software_cfg = self.object_config_lookup("Software", self.software)
            self.software_cfg.setup()
            self.supported_stages = {}
            for s in self.stages:
                self.supported_stages[s] = self.object_config_lookup("Bootstages", s)

                # now check software
                self.software_cfg = self.object_config_lookup("Software", self.software)


class Bootstages(ConfigObject):
    required_fields = ["name", "stagename", "image", "elf"]

    def setup(self):
        if not self.attr_exists("setup_done"):
            self.setup_done = True
            self.post_build_setup_done = False
            self.set_default("minpc", -1)
            self.set_default("maxpc", -1)
            self.set_default("exitpc", -1)
            self.set_default("entrypoint", -1)
            self.set_default("image_size", -1)
            self.boot_cfg = Main.get_bootloader_cfg()
            self.elfname = os.path.basename(self.elf)
            self.elf = os.path.join(self.boot_cfg.software_cfg.root, self.elf)
            self.image = os.path.join(self.boot_cfg.software_cfg.root, self.image)

    def post_build_setup(self):
        if not self.post_build_setup_done:
            self.post_build_setup_done = True
            (lo, hi) = pure_utils.get_min_max_pcs(Main.cc, self.elf)
            if self.minpc < 0:
                self.minpc = lo
            if self.maxpc < 0:
                self.maxpc = hi
            if self.entrypoint < 0:
                self.entrypoint = pure_utils.get_entrypoint(Main.cc, self.elf)
            if self.image_size < 0:
                self.image_size = pure_utils.get_image_size(self.image)
            if type(self.exitpc) == str:
                stage = self.object_config_lookup("Bootstages", self.exitpc)
                if not stage.post_build_setup_done:
                    stage.post_build_setup()
                self.exitpc = stage.entrypoint


path = os.path.dirname(os.path.realpath(__file__))
config = os.path.join(os.path.expanduser("~"), ".bootsuite.yaml")
if not os.path.exists(config):
    config = os.path.join(path, "bootsuite.yaml")
with open(config, "r") as f:
    settings = yaml.load(f)
    for (k, v) in settings.iteritems():
        if k in configtypes.keys():
            if type(v) == list:
                for i in v:
                    configtypes[k](i)
            else:
                configtypes[k](v)
if "Main" not in registry.keys():
    raise Exception("We are missing 'Main' configuration data")
globals()["Main"] = registry["Main"][0]
Main.config = config


# first setup main, then bootloaders, then everything else
Main.setup()

for (k, v) in registry.iteritems():
    if k == "Bootloader":
        globals()[k] = v
        for instance in v:
            instance.setup()

for (k, v) in registry.iteritems():
    if not k == "Main" or k == "Bootloader":
        globals()[k] = v
        for instance in v:
            instance.setup()
