def get_relocation(Main, stage, name, RelocDescriptor, utils):
    infos = []
    elf = stage.elf
    cc = Main.cc
    r = RelocDescriptor("clk_code", None, None, None, None,
                        None, stage, True, "go_to_speed")
    dstaddr = r.dstaddr
    srcdir = Main.get_runtime_config("temp_target_src_dir")
    cmd = "%sgdb --cd=%s " \
          "-ex 'x/i 0x%x' --batch --nh --nx  %s" % (cc,
                                                    srcdir,
                                                    dstaddr, elf)
    output = Main.shell.run_multiline_cmd(cmd)
    output = output[0].strip()
    output = output.split(';')[1].strip()
    dstaddr = long(output, 16)
    # now get value at this address
    cmd = "%sgdb --cd=%s " \
          "-ex 'x/wx 0x%x' --batch --nh --nx  %s" % (cc, srcdir,
                                                     dstaddr, elf)
    output = Main.shell.run_multiline_cmd(cmd)
    output = output[0].strip()
    dstaddr = long(output.split(':')[1].strip(), 0)

    r.set_reloffset(dstaddr - r.cpystartaddr)
    if name == "clk_code":
        return r.get_row_information()

    if stage.stagename == 'main' and name == "reloc_code":
        cpystartaddr = utils.get_symbol_location("__image_copy_start", stage)
        cpyendaddr = utils.get_symbol_location("__image_copy_end", stage)
        r =  RelocDescriptor("reloc_code", None,
                            None, cpystartaddr,
                            cpyendaddr, -1, stage, True)
        reloffset = 0x9ff00000 - 0x800a0000  # hand calculated
        r.set_reloffset(reloffset)
        mod = r.relmod
        infos.append(r.get_row_information())

        # keep origional c_runtime_cpu_setup since it is run from orig location
        # after relocation. "unrelocate" it but keep orig
        name = "c_runtime_cpu_setup"
        (start, end) = utils.get_symbol_location_start_end(name, stage)
        hereaddr = utils.get_symbol_location("here", stage)
        startrel = (start + reloffset) % mod
        endrel = (end + reloffset) % mod
        r = RelocDescriptor("here", hereaddr, hereaddr,
                            startrel, endrel, start,
                            stage, False, name)
        r.set_reloffset(-1*reloffset)
        return r.get_row_information()
