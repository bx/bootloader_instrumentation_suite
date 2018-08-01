from enum import Enum

cmds = Enum("CmdTyp", ["print_build_commands", "build_software", "create", "list_policies", "import_policy",
                       "setup_trace", "run_new_trace", "do_trace", "list_test_runs", "print_trace_commands",
                       "postprocess_trace", "hook", "list_instances"])
