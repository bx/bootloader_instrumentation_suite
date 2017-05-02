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


def bbxmqemu(main, boot_config,
             policies,
             hw_config,
             host_software_config,
             instance_id,
             test_id,
             data_root,
             tracetype,
             quick):
    qemu = os.path.join(host_software_config.root, host_software_config.binary)
    cmds = []
    run_cmd = "%s -M %s -sd %s -clock vm " \
              "-S -s" % (qemu, hw_config.machinename,
                         main.get_config('sd_image'))
    cfg = {'gdb_commands': ["target extended-remote :1234"]}
    deps = []
    targets = []
    main_cfgs = {}
    if tracetype == "watchpoint":
        if len(list(policies.iterkeys())) > 1:
            raise Exception("watchpoint traces only supports one stage at a time")
        for s in policies.iterkeys():
            f = os.path.join(data_root, "trace-events.raw")
            main_cfgs["trace_events_output"] = f
            d = os.path.join(data_root, "trace-events.completed")
            main_cfgs["trace_events_done"] = d
            targets = [f]
            n = main.get_config("trace_events_file", s)
            deps = [n]
            run_cmd += " -nographic -trace events=%s,file=%s" % (n, f)
    else:
        run_cmd += " -daemonize"
    deps.append(qemu)
    cmds.append(("long_running", run_cmd))
    return cmds + [('configs', cfg), ("set_config", main_cfgs),
                   ('file_dep', deps), ("targets", targets)]


def breakpoint(main, configs,
               policies,
               instance_id,
               test_id,
               data_root,
               quick):
    gdb = main.cc + "gdb"
    hookwrite_src = os.path.join(main.test_suite_path, "hook_write.py")
    stagesetters = " ".join(["-ex 'hookwrite stages %s' -ex 'hookwrite substages %s %s'"
                             " -ex 'hookwrite until -s %s'" % (s.stagename,
                                                               s.stagename,
                                                               v,
                                                               s.stagename)
                             for (s, v) in policies.iteritems()])
    additional_cmds = " ".join("-ex '%s'" % s for s in configs['gdb_commands'])

    cmd = "%s %s -ex 'python execfile(\"%s\")' -ex 'hookwrite test_instance %s' " \
          "-ex 'hookwrite test_trace %s' %s " \
          "-ex 'hookwrite kill' -ex 'hookwrite go' -ex 'q'" % (gdb,
                                                               additional_cmds,
                                                               hookwrite_src,
                                                               instance_id,
                                                               test_id,
                                                               stagesetters)

    deps = []
    targets = []
    done_commands = []
    main_cfgs = {}
    trace_dbs = {}
    trace_db_done = {}
    for s in policies.iterkeys():
        deps.extend([main.get_config("staticdb", s),
                     main.get_config("staticdb_done", s),
                     main.get_config("policy_db", s),
                     main.get_config("policy_db_done", s)])
        trace_dbs[s.stagename] = os.path.join(data_root, "tracedb-%s.h5" % s.stagename)
        trace_db_done[s.stagename] = os.path.join(data_root, "tracedb-%s.completed" % s.stagename)
        done = trace_db_done[s.stagename]
        done_commands.append(("command", "touch %s" % done))
        targets.extend([trace_dbs[s.stagename], done])

    main_cfgs["trace_db"] = lambda s: trace_dbs[s.stagename]
    main_cfgs["trace_db_done"] = lambda s: trace_db_done[s.stagename]

    return [("interactive", cmd),
            ("set_config", main_cfgs)] + done_commands + [("targets", targets), ("file_dep", deps)]


def calltrace(main, configs,
              policies,
              instance_id,
              test_id,
              data_root,
              quick):
    gdb = main.cc + "gdb"
    orgfiles = {}
    done = {}
    additional_cmds = " ".join("-ex '%s'" % s for s in configs['gdb_commands'])
    calltrace_src = os.path.join(main.test_suite_path, "calltrace", "calltrace.py")
    targets = []
    blacklist = {'spl': ['__s_init_from_arm'],
                 'main': ['__s_init_from_arm', 'get_sp', 'setup_start_tag']}
    norec = ['sdelay']
    done_commands = []
    for s in policies.iterkeys():
        t = os.path.join(data_root,
                         "calltrace-%s.org" % s.stagename)
        d = os.path.join(data_root,
                         "calltrace-%s.completed" % s.stagename)
        targets.append(t)
        targets.append(d)
        done_commands.append(("command", "touch %s" % d))
        orgfiles[s.stagename] = t
        done[s.stagename] = d

    cmd = "%s %s -ex 'python execfile(\"%s\")'" % (gdb,
                                                   additional_cmds,
                                                   calltrace_src)
    stagenames = [s.stagename for s in policies.iterkeys()]
    cmd += " -ex 'calltrace stages %s'" % (" ".join(stagenames))
    for (k, v) in blacklist.iteritems():
        if k not in stagenames:
            continue
        cmd += " -ex 'calltrace blacklist %s %s'" % (k, " ".join(v))
        cmd += " -ex 'calltrace stage_log %s %s'" % (k, orgfiles[k])

    cmd += " -ex 'calltrace stages %s'" % " ".join(stagenames)
    cmd += " -ex 'calltrace test_instance %s'" % instance_id
    cmd += " -ex 'calltrace test_trace %s'" % test_id
    cmd += " -ex 'calltrace no_recursion %s'" % " ".join(norec)
    cmd += " -ex 'calltrace until -s main'"
    cmd += " -ex 'calltrace kill' -ex 'calltrace sourceinfo' -ex 'calltrace go'"
    main_cfgs = {}
    main_cfgs["calltrace_db"] = lambda s: orgfiles[s.stagename]
    main_cfgs["calltrace_done"] = lambda s: done[s.stagename]
    return [("interactive", cmd),
            ("set_config", main_cfgs)] + done_commands + [("targets", targets)]


def enforce(main, configs,
            policies,
            instance_id,
            test_id,
            data_root,
            quick):
    gdb = main.cc + "gdb"
    enforce_src = os.path.join(main.test_suite_path, "enforcement", "enforce.py")
    stagenames = [s.stagename for s in policies.iterkeys()]
    log = os.path.join(data_root, "enforce.log")
    done = os.path.join(data_root, "enforce.completed")
    stagesetters = " ".join(["-ex 'enforce substages %s %s'" % (s.stagename, v)
                             for (s, v) in policies.iteritems()])
    additional_cmds = " ".join("-ex '%s'" % s for s in configs['gdb_commands'])

    cmd = "%s %s -ex 'python execfile(\"%s\")' %s " % (gdb, additional_cmds, enforce_src,
                                                       stagesetters)
    cmd += "-ex 'enforce test_instance %s' " % instance_id
    cmd += "-ex 'enforce test_trace %s' " % test_id
    cmd += "-ex 'enforce log %s'" % log
    cmd += "-ex 'enforce until %s'" % stagenames[-1]
    cmd += "-ex 'enforce stages %s'" % " ".join(stagenames)
    cmd += "-ex 'enforce kill' -ex 'enforce go' -ex 'q'"

    deps = []
    targets = [log, done]
    done_commands = [("command", "touch %s" % done)]
    main_cfgs = {}
    for s in policies.iterkeys():
        deps.extend([main.get_config("staticdb", s),
                     main.get_config("staticdb_done", s),
                     main.get_config("policy_db", s),
                     main.get_config("policy_db_done", s)])

    main_cfgs["enforce_log"] = log
    main_cfgs["enforce_done"] = done

    return [("interactive", cmd),
            ("set_config", main_cfgs)] + done_commands + [("targets", targets), ("file_dep", deps)]


def watchpoint(main, configs,
               policies,
               instance_id,
               test_id,
               data_root,
               quick):

    gdb = main.cc + "gdb"
    additional_cmds = " ".join("-ex '%s'" % s for s in configs['gdb_commands'])
    if len(list(policies.iterkeys())) > 1:
        raise Exception("watchpoint traces only supports one stage at a time")
    deps = []
    targets = []
    done_commands = []
    for s in policies.iterkeys():
        breakpoint = "*0x%x" % s.exitpc
        f = main.get_config('trace_events_file', s)
        deps.append(f)
        done = main.get_config("trace_events_done")
        done_commands.append(("command", "touch %s" % done))
        targets.append(done)

    cmd = "%s -ex 'break %s' %s -ex 'c'" \
          "-ex 'monitor quit'" \
          "-ex 'q'" % (gdb,
                       breakpoint,
                       additional_cmds)

    return [("interactive", cmd)] + done_commands + [("targets", targets), ("file_dep", deps)]


def bbxmbaremetal(main, boot_config,
                  policies,
                  hw_config,
                  host_software_config,
                  instance_id,
                  test_id,
                  data_root,
                  tracetype,
                  quick):
    raise Exception("traces of type bbxmbaremetal are not yet supported")


def framac(main,
           configs,
           policies,
           instance_id,
           test_id,
           data_root,
           quick):
    return []


def bbxmframac(main, boot_config,
               policies,
               hw_config,
               host_software_config,
               instance_id,
               test_id,
               data_root,
               tracetype,
               quick):

    framac = os.path.join(host_software_config.root, host_software_config.binary)
    cmds = []
    patch_dir = os.path.join(data_root, "patches")
    callstacks = {}
    cmds.append(("command", "mkdir -p %s" % patch_dir))
    for stage in policies.iterkeys():
        if not stage.stagename == 'spl':
            raise Exception("does not support stage %s" % stage.stagename)
        else:
            callstacks[stage.stagemae] = os.path.join(data_root, "callstacks.txt")
            out = os.path.join(data_root, "framac-stdout.txt")
            policy_id = policies[stage]
            args = "--stage %s -e -u -b %s -c %s -t %s -T %s -I %s -P %s " % (stage.stagename,
                                                                              patch_dir,
                                                                              callstacks,
                                                                              out,
                                                                              test_id,
                                                                              instance_id,
                                                                              policy_id)
            cmd = "%s %s" % (framac, args)
            cmds.append(("command", cmd))
    configs = {"framac_callstacks", lambda s: callstacks[s.stagename]}
    return [("set_config", configs)] + cmds
