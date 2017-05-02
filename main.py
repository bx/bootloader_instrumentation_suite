#!/usr/bin/env python2
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

from config import Main


import argparse
import IPython
import glob
import os
import run_cmd
import sys
import doit_manager
import instrumentation_results_manager


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Bootloader test suite")
    cmds = parser.add_mutually_exclusive_group()
    cmds.add_argument('-c', '--create',
                      help='Create new results direcory, deleting any existing data if "\
                      "(-o specifies an existing directory)',
                      action='store_true', default=False)
    #cmds.add_argument('-s', '--pythonshell',
    #                  help='Drop to ipython shell after any directory initialization/creation',
    #                  action='store_true', default=False)
    #cmds.add_argument('-l', '--list_available_substages_tests', default=False, action='store_true')
    #cmds.add_argument('-p', '--printcommands',
    #                  help='Print commands that should be used to collect hardware tracing data',
    #                  action='store_true', default=False)
    #cmds.add_argument('-n', '--newtraceinstance',
    #                  help='Start/initialize new trace instance (otherwse will use" \
    #                  "/overwrite the last test instance)',
    #                  action='store_true', default=False)
    parser.add_argument('-q', '--quick',
                        help='Try to skip some steps to be faster',
                        action='store_true', default=False)

    #cmds.add_argument('-T', '--tracetestcmds',
    #                  help="Print commands needed to trace configuration. Must specify <spl/main"
    #                  ">, <QemuBreakpointTrace/QemuWatchpointTrace>",
    #                  action="append", nargs=2)
    cmds.add_argument('-B', '--build',
                      help="Name of software to clean, update git tree, "
                      "and build (openocd, u-boot, qemu))",
                      action="append")
    cmds.add_argument('-b', '--buildcommands',
                      help="Print build commands for the listed software "
                      "(openocd, u-boot, qemu))",
                      action="append")
    #cmds.add_argument('-a', '--allcommands', help="Print all commands",
    #                  action="store_true", default=False)
    #cmds.add_argument('-U', '--update_from_trace_data',
    #                  help='update databases from collected trace info',
    #                  action='store_true', default=False)

    cmds.add_argument('--print_policy', default=False, action='store_true')
    parser.add_argument('-o', '--testcfginstance',
                        help='Name of test config result directory to open, " \
                        "by default we use newest',
                        action='store', default="")
    # parser.add_argument('-H', '--enabled_hardware', action='append', default=[])
    parser.add_argument('-S', '--enabled_stages', action='append', default=[])

    #cmds.add_argument('--import_substages_test', action='store_true', default=False)
    #cmds.add_argument('--import_substages_test', action='store_true', default=False)
    #cmds.add_argument('--import_substages_policy', action='store_true', default=False)
    #cmds.add_argument('--print_trace_results', action='store_true', default=False)
    #cmds.add_argument('--delete_old_policies', action='store_true', default=False)
    #cmds.add_argument('--rerun_static', action='store_true', default=False)
    #cmds.add_argument('--consolidate_trace', action='store_true', default=False)
    #parser.add_argument('-u', '--enabled_substages', default='')

    class TraceAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            self.stages = list(Main.get_bootloader_cfg().supported_stages.itervalues())
            hw_classes = Main.get_hardwareclass_config().hardware_type_cfgs
            self.hw_classes = list(hw_classes.iterkeys())
            self.tracing_methods = {k: v.tracing_methods for k, v in hw_classes.iteritems()}
            # self.types = instrumentation_results_manager.TraceTaskLoader.supported_types
            self.nargs = 3
            self.selected = False
            self.d = {'stages': "spl",
                      "trace": "breakpoint",
                      "hw": "bbxmqemu",
                      # 'type': 'write'
            }
            #if dest == "run_trace":
            #    kwargs['default'] = self.d
            #else:
            kwargs['default'] = None
            #    print "None"
            super(TraceAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            if len(values) >= 3:
                stagename = values[0]
                hw = values[1]
                trace = values[2]
            else:
                hw = self.d["hw"]
                trace = self.d["trace"]
                stagename = self.d["stages"]
                # typ = self.d["type"]
            stagenames = [s.stagename for s in self.stages]
            if (stagename not in stagenames) and (not stagename == "all"):
                raise argparse.ArgumentError(self,
                                             "%s not a valid stage, must be one of %s" %
                                             (stagename, stagenames))
            if hw not in self.hw_classes:
                raise argparse.ArgumentError(self,
                                             "%s not a valid hardware name, must be one of %s" %
                                             (hw, str(self.hw_classes)))
            if trace not in self.tracing_methods[hw]:
                raise argparse.ArgumentError(self,
                                             "%s not a valid tracing method, must be one of %s" %
                                             (trace, str(self.tracing_methods[hw])))
            # if typ not in self.types:
            #     raise argparse.ArgumentError(self,
            #                                  "%s not a valid trace command, must be one of %s" %
            #                                  (typ, self.types))
            if stagename == "all":
                stages = [s.stagename for s in self.stages]
            else:
                stages = [stagename]
            setattr(namespace, self.dest, {'stages': stages,
                                           'hw': hw,
                                           'trace': trace})

    class SubstageFileAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            self.stages = list(Main.get_bootloader_cfg().supported_stages.itervalues())
            self.stagenames = [s.stagename for s in self.stages]
            self.nargs = 3
            if dest == "importpolicy":
                defaultdir = os.path.join(Main.hw_info_path,
                                          Main.get_hardwareclass_config().name,
                                          Main.get_bootloader_cfg().software)
                defaults = {s.stagename: (os.path.join(defaultdir, s.stagename, "substages.yml"),
                                          os.path.join(defaultdir, s.stagename, "memory_map.yml"))
                            for s in self.stages}
            else:
                defaults = {}
            kwargs['default'] = defaults
            super(SubstageFileAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            stagename = values[0]
            f = os.path.abspath(values[1])
            d = os.path.abspath(values[2])
            if stagename not in self.stagenames:
                raise argparse.ArgumentError(self,
                                             "%s not a valid stage, must be one of %s" %
                                             (stagename, str(self.stagenames)))
            # files = getattr(namespace, self.dest)
            getattr(namespace, self.dest)[stagename] = (f, d)

    class SubstageNameAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            stages = list(Main.get_bootloader_cfg().supported_stages.itervalues())
            self.stagenames = [s.stagename for s in stages]
            self.nargs = 2
            defaults = {'spl': None}
            kwargs['default'] = defaults
            super(SubstageNameAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            stagename = values[0]
            substages_name = values[1]
            if stagename not in self.stagenames:
                raise argparse.ArgumentError(self,
                                             "%s not a valid stage, must be one of %s" %
                                             (stagename, str(self.stagenames)))
            getattr(namespace, self.dest)[stagename] = substages_name


    cmds.add_argument('-I', '--importpolicy',
                      help="Stage name, path to file containing proposed substages, "
                      "and path to file containing region info",
                      action=SubstageFileAction, nargs=3)
    parser.add_argument('-P', '--policyfiles',
                        help="Stage name, path to file containing proposed substages, "
                        "and path to file containing region info",
                        action=SubstageFileAction, nargs=3)
    parser.add_argument('-n', '--policyname', action=SubstageNameAction, nargs=2)
    cmds.add_argument('-r', '--run_trace', action=TraceAction, nargs="*",
                      help="run new trace and collect data for specified stage "
                      "<stage>, hardware <hw>, tracing method <trace> "
                      "(-r <type> <stage> <hw> <trace>")
    parser.add_argument('-t', '--select_trace', default=None, action="store",
                      help="Select existing trace by name")
    cmds.add_argument('-T', '--postprocess_trace', default=[], action="append",
                      choices=instrumentation_results_manager.PostTraceLoader.supported_types,
                      help="Run trace postprocessing command")

    args = parser.parse_args()
    for l in ('enabled_stages',):  # , 'enabled_hardware'):
        if len(getattr(args, l)) == 0:
            setattr(args, l, ['all'])

    shell = run_cmd.Cmd()
    res = 0
    do_build = True if args.build or args.buildcommands else False
    import_policies = True
    if args.create:
        policies = args.policyfiles
    elif args.importpolicy:
        policies = args.importpolicy
    else:
        policies = args.policyname
        import_policies = False
    task_mgr = doit_manager.TaskManager(do_build, args.create,
                                        args.enabled_stages,
                                        policies,
                                        args.quick,
                                        args.run_trace,
                                        args.select_trace,
                                        import_policies,
                                        args.postprocess_trace)

    if args.build or args.buildcommands:
        targets = args.build if args.build else args.buildcommands
        ret = task_mgr.build(targets, True if args.build else False)
        sys.exit(ret)
    # t = TestConfigMgr(args.enabled_stages, args.enabled_hardware, args.quick)
    if args.create:
        task_mgr.create_test_instance()
    elif args.run_trace:
        task_mgr.run_trace()
    elif args.postprocess_trace:
        task_mgr.postprocess_trace()

    #
    # if args.create:
    #     t.create_new_test(args.substagefile, args.quick)
    # else:
    #     t.open_existing_test(test_cfg_name=args.testcfginstance,
    #                          trace_instance_name=args.traceinstance,
    #                          substagefiles=args.substagefile,
    #                          new_policy=args.import_substages_policy,
    #                          new_trace=args.update_from_trace_data,
    #                          edit=args.import_substages_test or args.import_substages_policy
    #                          or args.rerun_static
    #                          or args.consolidate_trace,
    #                          new_substage_trace=args.import_substages_test,
    #                          create_addr_space=args.import_substages_test or args.import_substages_policy,
    #                          delete_old_policies=args.delete_old_policies)
    # #if args.import_substages_test and args.substagefile:
    # #    for (stage, (f, d)) in args.substagefile.iteritems():
    # #        t.import_substages_test(Main.stage_from_name(stage), f, d)
    # #elif args.create or args.update:
    # #elif args.recreate:
    # #    t.run_static_analysis(args.quick)
    # if args.printcommands or args.allcommands:
    #     t.print_commands(args.allcommands)
    # elif args.update_from_trace_data:
    #     t.update_from_trace_data()
    # elif args.print_policy or args.import_substages_policy:
    #     t.print_policy(args.print_policy or args.import_substages_policy, args.print_trace_results)
    # elif args.rerun_static:
    #     t.run_static_analysis(True, True)
    # elif args.consolidate_trace:
    #     for h in t.enabled_hardware:
    #         for s in t.enabled_stages:
    #             db = t.current_test_cfg_instance.current_test_trace.get_trace_db_obj(s, h)
    #             db.consoladate_write_table("framac" in h.tracename.lower())
    # if args.list_available_substages_tests:
    #     test_cfg = t.current_test_cfg_instance
    #     for s in Main.get_bootloader_cfg().supported_stages.itervalues():
    #         tests = test_cfg.substage_mgr.list_available_substages_tests_for_stage(s)
    #         print "Available substage test for %s: %s" % (s.stagename, ", ".join(tests))

    # t.close_dbs()

    #     for s in args.build:
    #         s_cfg = Main.object_config_lookup("Software", s)
    #         if s_cfg is None:
    #             print "%s is not a valid software to build" % s
    #         else:
    #             build_cfg = s_cfg.build
    #             if build_cfg is None:
    #                 print "We do not know how to build %s" % s
    #             else:
    #                 build_cfg.do_all()

    # t = TestConfigMgr(args.enabled_stages, args.enabled_hardware)
    # if args.create:
    #     t.create_new_test(args.substagefile, args.quick)
    # else:
    #     t.open_existing_test(test_cfg_name=args.testcfginstance,
    #                          trace_instance_name=args.traceinstance,
    #                          substagefiles=args.substagefile,
    #                          new_policy=args.import_substages_policy,
    #                          new_trace=args.update_from_trace_data,
    #                          edit=args.import_substages_test or args.import_substages_policy
    #                          or args.rerun_static
    #                          or args.consolidate_trace,
    #                          new_substage_trace=args.import_substages_test,
    #                          create_addr_space=args.import_substages_test or args.import_substages_policy,
    #                          delete_old_policies=args.delete_old_policies)
    # #if args.import_substages_test and args.substagefile:
    # #    for (stage, (f, d)) in args.substagefile.iteritems():
    # #        t.import_substages_test(Main.stage_from_name(stage), f, d)
    # #elif args.create or args.update:
    # #elif args.recreate:
    # #    t.run_static_analysis(args.quick)
    # if args.printcommands or args.allcommands:
    #     t.print_commands(args.allcommands)
    # elif args.update_from_trace_data:
    #     t.update_from_trace_data()
    # elif args.print_policy or args.import_substages_policy:
    #     t.print_policy(args.print_policy or args.import_substages_policy, args.print_trace_results)
    # elif args.rerun_static:
    #     t.run_static_analysis(True, True)
    # elif args.consolidate_trace:
    #     for h in t.enabled_hardware:
    #         for s in t.enabled_stages:
    #             db = t.current_test_cfg_instance.current_test_trace.get_trace_db_obj(s, h)
    #             db.consoladate_write_table("framac" in h.tracename.lower())
    # if args.list_available_substages_tests:
    #     test_cfg = t.current_test_cfg_instance
    #     for s in Main.get_bootloader_cfg().supported_stages.itervalues():
    #         tests = test_cfg.substage_mgr.list_available_substages_tests_for_stage(s)
    #         print "Available substage test for %s: %s" % (s.stagename, ", ".join(tests))

    # t.close_dbs()
