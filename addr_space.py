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

import config
import pytable_utils
import utils
import substage
import intervaltree
import tables
import os
from config import Main
import csv
import StringIO
import parse_am37x_register_tables

register_map = {}


mmap_perms = tables.Enum(['rw', 'r', '?', 'rwx', 'x', 'w'])


mmap_type = tables.Enum(['special', 'reserved', 'rom', 'ram', 'registers',
                         'virtual', 'other', 'iva2.2'])


var_type = tables.Enum(['staticvar', 'register', 'othervar',
                        'heapvar', 'stackvar', 'text'])
vlist = ['rw', 'r', 'w', 'none', '?']
var_perms = tables.Enum(vlist)

perms = tables.Enum(vlist + ["rwx", "x", "rx"])


class MemMapEntry(tables.IsDescription):
    name = tables.StringCol(512)
    startaddr = tables.UInt32Col()
    endaddr = tables.UInt32Col()
    perms = tables.EnumCol(perms, '?', base='uint8')
    kind = tables.EnumCol(mmap_type, 'other', base='uint8')

#    new = tables.BoolCol()
#    in_process = tables.BoolCol()


class VarEntry(tables.IsDescription):
    name = tables.StringCol(512)
    startaddr = tables.UInt32Col()
    endaddr = tables.UInt32Col()
    substage = tables.Int16Col()
    kind = tables.EnumCol(var_type, 'othervar', base='uint8')
    perms = tables.EnumCol(var_perms, 'rw', base='uint8')
    rawkind = tables.StringCol(128)


class RegEntry(tables.IsDescription):
    name = tables.StringCol(512)
    address = tables.UInt32Col()
    width = tables.UInt8Col()
    reset = tables.StringCol(16)
    typ = tables.StringCol(16)
    offset = tables.UInt32Col()
    table = tables.StringCol(256)


class AddrSpaceInfo():
    def __init__(self):
        self.grpname = 'memory'
        self.base_memory_csv = Main.get_hardwareclass_config().base_mem_map
        self.mem_tablename = "memmap"
        self.reg_tablename = "regs"
        self.var_table = {}
        self.h5group = None
        self.h5file = None
        self.memmap_table = None
        self.reg_table = None

    def _var_tablename(self, stage):
        return "%s_vars" % stage.stagename

    def open_dbs(self, loc, create=False, csv=None):
        print "opening %s" % loc
        if create:
            self._create_tables(loc, csv)
        else:
            self._open_tables(loc)

    def _create_tables(self, dbloc, csv):
        dname = os.path.dirname(dbloc)

        if not os.path.isdir(dname):
            os.makedirs(dname)
        self.h5file = tables.open_file(dbloc, mode="w",
                                       title="addr space info")
        self.h5group = self.h5file.create_group("/", self.grpname, "")
        self.memmap_table = self.h5file.create_table(self.h5group, self.mem_tablename,
                                                     MemMapEntry, "")
        self.reg_table = self.h5file.create_table(self.h5group, self.reg_tablename,
                                                  RegEntry, "")
        self._create_memmap_table()
        self._create_reg_table(csv)
        for stage in Main.get_config('enabled_stages'):
            self._create_var_table(stage)

    def create_substage_memmap_table(self, substagecsv):
        with open(substagecsv) as csvfile:
            fields = ['name', 'startaddr', 'endaddr', 'perms', 'kind']
            reader = csv.DictReader(csvfile, fields)
            r = self.memmap_table.row
            for entry in reader:
                for f in fields:
                    if "addr" in f:
                        entry[f] = int(entry[f], 0)
                    else:
                        entry[f] = entry[f].strip().lower()
                        if f == 'perms':
                            entry[f] = getattr(mmap_perms, entry[f])
                        elif f == 'kind':
                            entry[f] = getattr(mmap_type, entry[f])
                    r[f] = entry[f]
                #r['substage'] = substage
                r.append()
        self.memmap_table.cols.startaddr.create_index(kind='full')
        self.memmap_table.cols.endaddr.create_index(kind='full')
        self.memmap_table.flush()

    def _create_memmap_table(self):
        self.create_substage_memmap_table(self.base_memory_csv)

    def print_memmap_table(self):
        for r in self.memmap_table.iterrows():
            perms = mmap_perms(r['perms'])
            kind = mmap_type(r['kind'])
            print "SECT: %s (0x%x -- 0x%x) (%s, %s)" % (r['name'],
                                                        r['startaddr'],
                                                        r['endaddr'],
                                                        perms, kind)

    def print_var_table(stage, self):
        for r in self.var_table[stage.stagename].iterrows():
            perms = var_perms(r['perms'])
            kind = var_type(r['kind'])
            print "VAR: %s (0x%x -- 0x%x) (%s, %s, %s) at substage %d" % (r['name'],
                                                                          r['startaddr'],
                                                                          r['endaddr'],
                                                                          perms, kind,
                                                                          r['rawkind'],
                                                                          r['substage'])

    def print_reg_table(self):
        for r in self.reg_table.iterrows():
            print "REG: %s (0x%x, %d bytes [offset %s]) (%s, %s) table %s" % (r['name'],
                                                                              r['address'],
                                                                              r['width'],
                                                                              r['offset'],
                                                                              r['typ'],
                                                                              r['reset'],
                                                                              r['table'])

    def _create_var_table(self, stage, substage=-1):
        fields = ["startaddr", "size", "kind", "name"]
        cc = Main.cc
        sname = stage.stagename
        tablename = self._var_tablename(stage)
        vtab = self.h5file.create_table(self.h5group, tablename,
                                        VarEntry, "")
        self.var_table[sname] = vtab
        #test_cfg = Main.testcfg_mgr.current_test_cfg_instance
        elf = Main.get_config("stage_elf", stage)
        cmd = "%snm -n -S %s" % (cc, elf)
        f = StringIO.StringIO(Main.shell.run_cmd(cmd))
        reader = csv.DictReader(f, fields, delimiter=" ",
                                lineterminator="\n", skipinitialspace=True)
        row = vtab.row
        for r in reader:
            if r['name'] is None:
                continue  # this means there is no listed size
            else:
                row['name'] = r['name'].strip()
                row['startaddr'] = int(r['startaddr'].strip(), 16)
                row['endaddr'] = row['startaddr'] + int(r['size'].strip(), 16)
                row['rawkind'] = r['kind'].strip()
                k = row['rawkind'].lower()
                if ('t' == k) or ('w' == k):
                    row['kind'] = getattr(var_type, 'text')
                else:
                    row['kind'] = getattr(var_type, 'staticvar')
                row['perms'] = getattr(var_perms, 'rw')
                row['substage'] = substage
                row.append()
        vtab.cols.startaddr.create_index(kind='full')
        vtab.cols.endaddr.create_index(kind='full')
        vtab.cols.substage.create_index(kind='full')
        vtab.flush()

    def _create_reg_table(self, csvfile):
        fields = ["startaddr", "size", "kind", "name"]
        cc = Main.cc
        (f, reader) = parse_am37x_register_tables.parsecsv(csvfile)
        row = self.reg_table.row
        for r in reader:
            row['address'] = int(r['address'].strip(), 16) if r['address'] else 0
            row["offset"] = int(r["offset"].strip(), 16) if r["offset"] else 0
            row["table"] = r["table"] if r["table"] else ""
            row["typ"] = r["typ"] if r["typ"] else ""
            row["width"] = int(r["width"]) if r["width"] else 0
            row["reset"] = r["reset"] if r["reset"] else ""
            row["name"] = r["name"] if r["name"] else ""
            if row['address'] == 0:
                print "addr not found in %s" % r

            row.append()
        f.close()
        self.reg_table.cols.address.create_index(kind='full')
        self.reg_table.flush()

    def _open_tables(self, loc):
        self.h5file = tables.open_file(loc, mode="r")
        self.h5group = self.h5file.get_node("/%s" % self.grpname)
        self.memmap_table = getattr(self.h5group, self.mem_tablename)
        for stage in Main.get_config('enabled_stages'):
            self.var_table[stage.stagename] = getattr(self.h5group, self._var_tablename(stage))
        self.reg_table = getattr(self.h5group, self.reg_tablename)

    def close_dbs(self, flush_only=False):
        self.memmap_table.flush()
        self.reg_table.flush()
        for v in self.var_table.itervalues():
            v.flush()
        self.h5file.flush()
        #print "grp %x" % id(self.h5group)
        if not flush_only:
            self.h5file.close()

    def resolve_variables(self, stage, intervals):
        def intervalfn(r):
            return (r['startaddr'], r['endaddr'])

        query = "(startaddr <= 0x{hi:x}) & (0x{lo:x} <= (endaddr + 1))"
        return self.resolve_table(intervals, self.var_table[stage.stagename], query, intervalfn)

    def resolve_regions(self, intervals):
        def intervalfn(r):
            return (r['startaddr'], r['endaddr'])

        query = "(startaddr <= 0x{hi:x}) & (0x{lo:x} <= (endaddr + 1))"
        return self.resolve_table(intervals, self.memmap_table, query, intervalfn)

    def resolve_table(self, intervals, table, format_string, intervalfn):
        variables = set()
        unknown_intervals = intervals
        # go through variables and registers, if in interval, add variable
        # row number to list and delete corresponding interval
        for i in intervals:
            lo = i.begin
            hi = i.end
            # find partial overlaps
            query = format_string.format(**{'lo': lo, 'hi': hi})
            #print query
            for r in table.where(query):
                (start, end) = intervalfn(r)

                varinter = intervaltree.Interval(start, end)

                # bug in pyinter if above is closedopen start end
                # subtracting {'_lower': 1, '_lower_value': 1224867840L, '_upper': 0, '_upper_value': 1224867844L} from
                # IntervalSet([1075904016, 1075904019), [1075904020, 1075904023), [1075904024, 1075904027), [1075904044, 1075904047), [1075904164, 1075904167), [1075904168, 1075904171), [1075904172, 1075904175), [1075904216, 1075904219), [1075904220, 1075904223), [1075904224, 1075904224), [1207967792, 1207967793), [1207967794, 1207967795), [1207967796, 1207967797), [1207967798, 1207967799), [1207967800, 1207967801), [1207967802, 1207967803), [1207967804, 1207967805), [1207967806, 1207967807), [1207967808, 1207967809), [1207967810, 1207967811), [1207967812, 1207967813), [1207967814, 1207967815), [1207967816, 1207967817), [1207967818, 1207967819), [1207967820, 1207967821), [1207967822, 1207967823), [1207967824, 1207967825), [1207967826, 1207967827), [1207967828, 1207967829), [1207967830, 1207967831), [1207967832, 1207967833), [1207967834, 1207967835), [1207967836, 1207967837), [1207967838, 1207967839), [1207967840, 1207967841), [1207967842, 1207967843), [1207967844, 1207967845), [1207967846, 1207967847), [1207967848, 1207967849), [1207967850, 1207967851), [1207967852, 1207967853), [1207967854, 1207967855), [1207967856, 1207967857), [1207967858, 1207967859), [1207967860, 1207967861), [1207967862, 1207967863), [1207967864, 1207967865), [1207967866, 1207967867), [1207967868, 1207967869), [1207967870, 1207967871), [1207967872, 1207967873), [1207967874, 1207967875), [1207967876, 1207967877), [1207967878, 1207967879), [1207967880, 1207967881), [1207967882, 1207967883), [1207967884, 1207967885), [1207967886, 1207967887), [1207967888, 1207967889), [1207967890, 1207967891), [1207967892, 1207967893), [1207967894, 1207967895), [1207967896, 1207967897), [1207967898, 1207967899), [1207967900, 1207967901), [1207967902, 1207967903), [1207967904, 1207967905), [1207967906, 1207967907), [1207967908, 1207967909), [1207967910, 1207967911), [1207967912, 1207967913), [1207967914, 1207967915), [1207967916, 1207967917), [1207967918, 1207967919), [1207967920, 1207967921), [1207967922, 1207967923), [1207967924, 1207967925), [1207967926, 1207967927), [1207967928, 1207967929), [1207967930, 1207967931), [1207967932, 1207967933), [1207967934, 1207967935), [1207967936, 1207967937), [1207967938, 1207967939), [1207967940, 1207967941), [1207967942, 1207967943), [1207967944, 1207967945), [1207967946, 1207967947), [1207967948, 1207967949), [1207967950, 1207967951), [1207967952, 1207967953), [1207967954, 1207967955), [1207967956, 1207967957), [1207967958, 1207967959), [1207967960, 1207967961), [1207967962, 1207967963), [1207967964, 1207967965), [1207967966, 1207967967), [1207967968, 1207967969), [1207967970, 1207967971), [1207967972, 1207967973), [1207967974, 1207967975), [1207967976, 1207967977), [1207967978, 1207967979), [1207967980, 1207967981), [1207967982, 1207967983), [1207967984, 1207967985), [1207967986, 1207967987), [1207967988, 1207967989), [1207967990, 1207967991), [1207967992, 1207967993), [1207967994, 1207967995), [1207967996, 1207967997), [1207967998, 1207967999), [1207968000, 1207968001), [1207968002, 1207968003), [1207968004, 1207968005), [1207968006, 1207968007), [1207968008, 1207968009), [1207968010, 1207968011), [1207968012, 1207968013), [1207968014, 1207968015), [1207968016, 1207968017), [1207968018, 1207968019), [1207968020, 1207968021), [1207968022, 1207968023), [1207968024, 1207968025), [1207968026, 1207968027), [1207968028, 1207968029), [1207968030, 1207968031), [1207968032, 1207968033), [1207968034, 1207968035), [1207968036, 1207968037), [1207968038, 1207968039), [1207968040, 1207968041), [1207968042, 1207968043), [1207968044, 1207968045), [1207968046, 1207968047), [1207968048, 1207968049), [1207968050, 1207968051), [1207968052, 1207968053), [1207968054, 1207968055), [1207968056, 1207968057), [1207968058, 1207968059), [1207968060, 1207968061), [1207968062, 1207968063), [1207968064, 1207968065), [1207968066, 1207968067), [1207968068, 1207968069), [1207968070, 1207968071), [1207968072, 1207968073), [1207968074, 1207968075), [1207968076, 1207968077), [1207968078, 1207968079), [1207968080, 1207968081), [1207968082, 1207968083), [1207968084, 1207968085), [1207968086, 1207968087), [1207968088, 1207968089), [1207968090, 1207968091), [1207968092, 1207968093), [1207968094, 1207968095), [1207968096, 1207968097), [1207968098, 1207968099), [1207968100, 1207968101), [1207968102, 1207968103), [1207968104, 1207968105), [1207968106, 1207968107), [1207968108, 1207968109), [1207968110, 1207968111), [1207968112, 1207968113), [1207968114, 1207968115), [1207968116, 1207968117), [1207968118, 1207968119), [1207968120, 1207968121), [1207968122, 1207968123), [1207968124, 1207968125), [1207968126, 1207968127), [1207968128, 1207968129), [1207968130, 1207968131), [1207968132, 1207968133), [1207968134, 1207968135), [1207968136, 1207968137), [1207968138, 1207968139), [1207968140, 1207968141), [1207968142, 1207968143), [1207968144, 1207968145), [1207968146, 1207968147), [1207968148, 1207968149), [1207968150, 1207968151), [1207968152, 1207968153), [1207968154, 1207968155), [1207968156, 1207968157), [1207968158, 1207968159), [1207968160, 1207968161), [1207968162, 1207968163), [1207968164, 1207968165), [1207968166, 1207968167), [1207968168, 1207968169), [1207968170, 1207968171), [1207968172, 1207968173), [1207968174, 1207968175), [1207968176, 1207968177), [1207968178, 1207968179), [1207968180, 1207968181), [1207968182, 1207968183), [1207968184, 1207968185), [1207968186, 1207968187), [1207968188, 1207968189), [1207968190, 1207968191), [1207968192, 1207968193), [1207968194, 1207968195), [1207968196, 1207968197), [1207968198, 1207968199), [1207968200, 1207968201), [1207968202, 1207968203), [1207968204, 1207968205), [1207968206, 1207968207), [1207968208, 1207968209), [1207968210, 1207968211), [1207968212, 1207968213), [1207968214, 1207968215), [1207968216, 1207968217), [1207968218, 1207968219), [1207968220, 1207968221), [1207968222, 1207968223), [1207968224, 1207968225), [1207968226, 1207968227), [1207968230, 1207968231), [1207968232, 1207968233), [1207968234, 1207968235), [1207968236, 1207968237), [1207968238, 1207968239), [1207968240, 1207968241), [1207968242, 1207968243), [1207968244, 1207968245), [1207968246, 1207968247), [1207968248, 1207968249), [1207968250, 1207968251), [1207968252, 1207968253), [1207968254, 1207968255), [1207968256, 1207968257), [1207968258, 1207968259), [1207968260, 1207968261), [1207968262, 1207968263), [1207968264, 1207968265), [1207968266, 1207968267), [1207968268, 1207968269), [1207968270, 1207968271), [1207968272, 1207968273), [1207968274, 1207968275), [1207968276, 1207968277), [1207968278, 1207968279), [1207968280, 1207968281), [1207968282, 1207968283), [1207968284, 1207968285), [1207968286, 1207968287), [1207968288, 1207968289), [1207968290, 1207968291), [1207968292, 1207968293), [1207968294, 1207968295), [1207968296, 1207968297), [1207968298, 1207968299), [1207968300, 1207968301), [1207968302, 1207968303), [1207968304, 1207968305), [1207968306, 1207968307), [1207968308, 1207968309), [1207968310, 1207968311), [1207968312, 1207968313), [1207968314, 1207968315), [1207968316, 1207968317), [1207968318, 1207968319), [1207968320, 1207968321), [1207968322, 1207968323), [1207968324, 1207968325), [1207968326, 1207968327), [1207968328, 1207968329), [1207968330, 1207968331), [1207968332, 1207968333), [1207968334, 1207968335), [1207968336, 1207968337), [1207968338, 1207968339), [1207968340, 1207968341), [1207968342, 1207968343), [1207968344, 1207968345), [1207968346, 1207968347), [1207968348, 1207968349), [1207968350, 1207968351), [1207968352, 1207968353), [1207968354, 1207968355), [1207968356, 1207968357), [1207968372, 1207968375), [1207968472, 1207968475), [1207969056, 1207969059), [1207969240, 1207969241), [1207969242, 1207969243), [1207969244, 1207969245), [1207969246, 1207969247), [1207969248, 1207969249), [1207969250, 1207969251), [1207969252, 1207969253), [1207969254, 1207969255), [1207969256, 1207969257), [1207969258, 1207969259), [1207969260, 1207969261), [1207969262, 1207969263), [1207969264, 1207969265), [1207969266, 1207969267), [1207969268, 1207969269), [1207969270, 1207969271), [1207969272, 1207969273), [1207969274, 1207969275), [1207970304, 1207970305), [1207970306, 1207970307), [1207970308, 1207970309), [1207970310, 1207970311), [1207970314, 1207970315), [1207970316, 1207970317), [1207970318, 1207970319), [1207970320, 1207970321), [1207970322, 1207970323), [1207970324, 1207970325), [1207970326, 1207970327), [1207970328, 1207970329), [1207970330, 1207970331), [1207970380, 1207970381), [1207975936, 1207975939), [1207975940, 1207975943), [1207976000, 1207976003), [1207976004, 1207976007), [1207978244, 1207978247), [1207978304, 1207978307), [1207978308, 1207978311), [1207978496, 1207978499), [1207978504, 1207978507), [1207978512, 1207978515), [1207978516, 1207978519), [1207978520, 1207978523), [1207978560, 1207978563), [1207978816, 1207978819), [1207979008, 1207979011), [1207979024, 1207979027), [1207979072, 1207979075), [1207979264, 1207979267), [1207979268, 1207979271), [1207979328, 1207979331), [1207979332, 1207979335), [1207979336, 1207979339), [1207979340, 1207979343), [1207979344, 1207979347), [1207979520, 1207979523), [1207979536, 1207979539), [1207979584, 1207979587), [1207979776, 1207979779), [1207979792, 1207979795), [1207979840, 1207979843), [1207980032, 1207980035), [1207980048, 1207980051), [1207980096, 1207980099), [1207980352, 1207980355), [1207981056, 1207981059), [1207981072, 1207981075), [1208418308, 1208418309), [1208418312, 1208418313), [1208418328, 1208418329), [1208418332, 1208418332), [1208418336, 1208418337), [1208418340, 1208418341), [1208418344, 1208418345), [1208418348, 1208418349), [1208418352, 1208418353), [1208418356, 1208418357), [1208418360, 1208418361), [1208418364, 1208418365), [1208598788, 1208697139), [1208697140, 1208697143), [1208697152, 1208697155), [1211133248, 1211133251), [1211134576, 1211134579), [1211187272, 1211187275), [1211203620, 1211203623), [1211203628, 1211203631), [1224867840, 1224867840), [1224867844, 1224867844), [1224867848, 1224867848), [1224867852, 1224867852), [1224867856, 1224867856), [1224867872, 1224867872), [1224941604, 1224941607), [1224941612, 1224941615), [1225097424, 1225097427), [1744896080, 1744896083), [1744896088, 1744896091), [1744896096, 1744896099), [1744896104, 1744896107), [1744905288, 1744905291), [1744905296, 1744905299), [1744905304, 1744905307), [1744906312, 1744906315), [1744906320, 1744906323), [1744906328, 1744906331), [1744906368, 1744906371), [1744912456, 1744912459), [1744912464, 1744912467), [1744912472, 1744912475), [1811939400, 1811939403), [1828716560, 1828716563), [1828716608, 1828716611), [1828716612, 1828716615), [1828716640, 1828716643), [1828716656, 1828716659), [1828716672, 1828716763), [1845493776, 1845493779), [1845493784, 1845493787), [1845493788, 1845493791), [1845493824, 1845493827), [1845493840, 1845493843), [1845493856, 1845493859), [1845493860, 1845493863), [1845493864, 1845493867), [1845493868, 1845493871), [1845493872, 1845493875), [1845493876, 1845493879), [1845493880, 1845493883), [1845493884, 1845493884), [1845493888, 1845493888), (2147483650, 2147483651))
                unknown_intervals = unknown_intervals - varinter
                variables.add(r.nrow)
        return (unknown_intervals, list(variables))

    def resolve_registers(self, intervals):
        def intervalfn(r):
            #print "resolve reg %s 0x%x %d 0x%x" % (r['name'], r['address'], r['width'], r['width']/8)
            return (r['address'], r['address'] + (r['width'] / 8))
        query = "(address <= 0x{hi:x}) & (0x{lo:x} <= (address + (width / 8 )))"
        return self.resolve_table(intervals, self.reg_table, query, intervalfn)

    @classmethod
    def intervalset_size(cls, s):
        sz = 0
        for i in s:
            sz += i.end - i.begin
        return sz

    def resolve_all_substages(self, hw, ssdb):
        substages = ssdb.substage_numbers()
        ssdict = {s: (intervaltree.IntervalTree(), []) for s in substages}
        results = {i.tracename: ssdict for i in hw}
        for h in hw:
            print '--------%s----------' % h.tracename
            intervals = ssdb.get_intervals(h)
            for s in intervals.iterkeys():
                (unknown_intervals, variables) = self.resolve_variables(intervals[s])
                (unknown_intervals, registers) = self.resolve_registers(unknown_intervals)
                (unknown_intervals, regions) = self.resolve_regions(unknown_intervals)
                results[h.tracename][s] = (unknown_intervals, variables, registers)
                print "stage %s (%d): %s" % (s, len(variables),
                                             [self.var_table[ssdb.stage.stagename][r]['name'] for r in variables])
                print "stage %s (%d): %s" % (s, len(registers),
                                             [self.reg_table[r]['name'] for r in registers])
                print "stage %s (%d): %s" % (s, len(regions),
                                             [self.memmap_table[r]['name'] for r in regions])
                print "interval[%s] size %s" % (s, self.intervalset_size(intervals[s]))
                print "unknown interval[%s] size %s" % (s,
                                                        self.intervalset_size(unknown_intervals))
        return results
