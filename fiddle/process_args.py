import argparse
import os
import sys
from config import Main
import instrumentation_results_manager
import doit_manager
import run_cmds


class FiddleArgParser(argparse.ArgumentParser):    
    def __init__(self, name="", plugin_only=False,
                 arg_parsers=[]):
        self.name = name
        parser = argparse.ArgumentParser(self.name)
        class SubstageFileAction(argparse.Action):
            def __init__(self, option_strings, dest, **kwargs):
                self.stages = Main.stages
                self.stagenames = [s.stagename for s in self.stages]
                if len(self.stages) == 1:
                    self.nargs = 2
                else:
                    self.nargs = 3

                name = Main.get_hardwareclass_config().name
                path = Main.get_hardwareclass_config().hw_info_path
                defaultdir = os.path.join(Main.get_hardwareclass_config().hw_info_path, name)

                self.sdefaults = {}
                kwargs['default'] = self.sdefaults
                super(SubstageFileAction, self).__init__(option_strings, dest, **kwargs)

            def __call__(self, parser, namespace, values, option_string=None):
                stagename = values[0]
                f = os.path.abspath(values[1])
                d = os.path.abspath(values[2])
                if stagename not in self.stagenames:
                    raise argparse.ArgumentError(self,
                                                 "%s not a valid stage, must be one of %s" %
                                                 (stagename, str(self.stagenames)))
                if not os.path.exists(f):
                    raise argparse.ArgumentError("Substage definition file I am trying to import from '%s' not found" % f)
                if not os.path.exists(d):
                    raise argparse.ArgumentError("Region definition file I am trying to import from '%s' not found" % d)

                getattr(namespace, self.dest)[stagename] = (f, d)

        class SubstageNameAction(argparse.Action):
            def __init__(self, option_strings, dest, **kwargs):
                stages = Main.stages
                self.stagenames = [s.stagename for s in stages]
                self.nargs = 2
                defaults = {}
                kwargs['default'] = defaults
                super(SubstageNameAction, self).__init__(option_strings, dest, **kwargs)

            def __call__(self, parser, namespace, values, option_string=None):
                stagename = values[0]
                policy_name = values[1]
                if stagename not in self.stagenames:
                    raise argparse.ArgumentError(self,
                                                 "%s not a valid stage, must be one of %s" %
                                                 (stagename, str(self.stagenames)))
                getattr(namespace, self.dest)[stagename] = policy_name
        if plugin_only:
            cmds = None
        else:
            cmds = parser.add_mutually_exclusive_group()
            cmds.add_argument('-c', '--create',
                              help='Create new result directory for current instance of '\
                              'software specified in configuration',
                              action='store_true', default=False)

            cmds.add_argument('-I', '--import_policy',
                              help="Import policy (substage and region definitions) into instance. ' \
                              'Requires stage name, path to file containing proposed substages, "
                              "and path to file containing region info", nargs="*", default={},
                              action=SubstageFileAction)
            cmds.add_argument('-L', '--list_policies', default=False, action="store_true",
                              help="Lists instance's imported policies",)

            cmds.add_argument('-B', '--build_software',
                              help="Name of software to clean, update git tree, "
                              "and build (openocd, u-boot, qemu))",
                              action="append", default=[])
            cmds.add_argument('-b', '--print_build_commands',
                              help="Print build commands for software",
                              default=[], action="append")
            cmds.add_argument('-S', '--setup_trace', action="store_true",
                              default=False)
            cmds.add_argument('-R', '--run_new_trace', action="store_true",
                              default=False)
            cmds.add_argument('-D', '--do_trace', action="store_true",
                              help="Performs trace if not already performed",
                              default=False)
            cmds.add_argument('--list_instances', action="store_true",
                              default=False)
            cmds.add_argument('-l', '--list_test_runs', action="store_true",
                              default=False)
            cmds.add_argument('-p', '--postprocess_trace', default=[], action="append",
                              choices=instrumentation_results_manager.PostTraceLoader.supported_types,
                              help="Run trace postprocessing command")
            cmds.add_argument('-P', '--print_trace_commands', action='store_true',
                                help='Prints commands used to produce trace')

        parser.add_argument('-i', '--select_instance',
                            help='Name test instance use, " \
                            "by default we use newest',
                            action='store', default=None)

        c = Main.get_hardwareclass_config()
        if not isinstance(c.default_host, str):
            raise Exception("check your configuration, default host should be a string")
        host = Main.object_config_lookup("HostConfig", c.default_host)
        parser.add_argument('-t', '--select_trace', action="store",
                            help="Select existing instance's trace by name")
        parser.add_argument("-T", "--trace_methods",  action="append",
                            choices=[m.name for m in Main.object_config_lookup("TraceMethod")])
        parser.add_argument('-s', '--stages', action='append', default=[])
        parser.add_argument('-n', '--select_policy', action=SubstageNameAction, nargs=2)
        parser.add_argument('-H', '--host', action="store", default=host.name,
                            choices=[m.name for m in Main.object_config_lookup("HostConfig")])
        parser.add_argument('-v', '--verbose', action="store_true")
        parser.add_argument('-k', '--keep_temp_files', action="store_true")
        parser.add_argument('-q', '--quick',
                            help='Try to skip some steps to be faster',
                            action='store_true', default=False)
        for (n, ks) in arg_parsers:
            parser.add_argument(*n, **ks)
        args = parser.parse_args()
        args.hook = ""
        other = None
        cmd = None
        for c in list(run_cmds.cmds):
            n =  c._name_
            if (not plugin_only) and getattr(args, n, None):
                cmd = c
                break
            else:
                setattr(args, n, None)
        if plugin_only:
            cmd =  run_cmds.cmds.hook
        if "all" in args.stages:
            args.stages = Main.stages
        elif not args.stages:
            args.stages = [s.stagename for s in Main.default_stages]
        if args.print_build_commands or args.build_software:
            other = args.print_build_commands + args.build_software
        if args.import_policy:
            policy = args.import_policy
        else:
            policy = args.import_policy
        if not args.trace_methods:
             args.trace_methods=host.default_tracing
        self.parser = parser
        self.args = args
        self.other = other
        self.cmd = cmd
        self.policy = policy
        self._tm = None

    def task_manager(self):
        if self._tm is None:
            self._tm =  doit_manager.TaskManager(self.cmd,
                                                 self.args.select_instance,
                                                 self.args.select_trace,
                                                 self.args.host,
                                                 self.args.trace_methods,
                                                 self.args.stages,
                                                 self.policy,
                                                 self.args.postprocess_trace,
                                                 not self.args.keep_temp_files,
                                                 self.args.quick,
                                                 self.other,
                                                 self.args.verbose)
        return self._tm
