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


def get_rows(table, query):
    indices = table.get_where_list(query)  # [r for r in rows]
    return [table[i] for i in indices]


def query(table, query):
    return table.where(query)  # [r for r in rows]


def _print(line):
    print line


def has_results(table, query):
    res = table.where(query)
    try:
        next(res)
        return True
    except StopIteration:
        return False


def get_sorted(table, col, field=None):
    return table.read_sorted(col, field=field)


def get_unique_result(table, query):
    res = get_rows(table, query)
    if len(res) > 1:
        raise Exception("more than 1 result matching query %s in table %s" %
                        (query, str(table)))
    elif len(res) == 0:
        return None
    else:
        return res[0]
