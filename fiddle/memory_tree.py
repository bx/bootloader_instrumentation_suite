import intervaltree


def int_repr(self):
    if self.end > 0xFFFFFFFF:
        ct = 16
    else:
        ct = 8
    fmt = "({0:%dX}, {1:%dX})" % (ct, ct)
    return fmt.format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr

# export version of intervaltree that prints all values as hex
globals()['intervaltree'] = intervaltree
