from ctypes import *
from fuzzer import InjectorResults, capstone_dissasembler
from binascii import hexlify, unhexlify
import curses
import time

DATA = "./data/"
LOG = DATA + "core-i7-8565U-log"


class Result:
    SIGNALS = {4: "sigill", 5: "sigtrap",
               7: "sigbus", 8: "sigfpe", 11: "sigsegv"}

    def __init__(self, raw, valids, lengths, disassembly_lengths, signums, sicodes, prefixes):
        self.raw = raw
        self.valids = valids
        self.lengths = lengths
        self.dl = disassembly_lengths
        self.signums = signums
        self.signals = [self.SIGNALS[s] for s in signums]
        self.sicodes = sicodes
        self.prefixes = prefixes


class Catalog:
    def __init__(self, d={}, r=None, collapsed=True, base="", count=0, valids=(), lengths=(), signums=(), sicodes=(), prefixes=()):
        self.dict = d  # son catalogs
        self.result = r  # instruction in my index level
        self.collapsed = collapsed
        self.base = base

        self.count = count
        self.valids = valids
        self.lengths = lengths
        self.signums = signums
        self.sicodes = sicodes
        self.prefixes = prefixes


class Summary:
    def __init__(self):
        self.current = InjectorResults()
        self.catalog = None
        self.text = None
        self.lookup = None

    def summarize(self):
        instructions = self.read_file()
        self.catalog = build_catalog(instructions, 0, '')
        self.catalog.collapsed = False
        self.text, self.lookup = build_text_catalog(self.catalog, 0)

    def read_file(self):
        with open(LOG, "rb") as f:
            bytes_polled = f.readinto(self.current)
            dict = {}
            while bytes_polled == sizeof(self.current):
                prefixes = get_prefixes(self.current.raw_ins)
                count_prefixes = len(prefixes)
                striped = hexlify(strip_prefixes(self.current.raw_ins))[
                    :(self.current.len - len(prefixes))*2]
                if not prefixes:
                    prefixes.append('_')
                if striped in dict:
                    dict[striped].valids.add(self.current.valid)
                    dict[striped].lengths.add(self.current.len-count_prefixes)
                    dict[striped].dl.add(self.current.disas_len if self.current.disas_len == 0 else self.current.disas_len-count_prefixes)
                    dict[striped].signums.add(self.current.signum)
                    dict[striped].sicodes.add(self.current.si_code)
                    dict[striped].prefixes.update(prefixes)
                else:
                    dict[striped] = Result(unhexlify(striped),
                                           set([int(self.current.valid)]),
                                           set([int(self.current.len-count_prefixes)]),
                                           set([int(self.current.disas_len if self.current.disas_len == 0 else self.current.disas_len-count_prefixes)]),
                                           set([int(self.current.signum)]),
                                           set([int(self.current.si_code)]),
                                           set(prefixes))
                bytes_polled = f.readinto(self.current)

        return list(dict.values())


def build_catalog(instructions, index, base):
    valids = merge_sets(instructions, 'valids')
    lengths = merge_sets(instructions, 'lengths')
    signums = merge_sets(instructions, 'signums')
    sicodes = merge_sets(instructions, 'sicodes')
    prefixes = merge_sets(instructions, 'prefixes')

    c = Catalog({}, None, True, base, len(instructions),
                valids, lengths, signums, sicodes, prefixes)

    for i in instructions:
        if len(i.raw) > index:
            byte = hexlify(i.raw[index:index+1]).decode()
            if byte in c.dict:
                c.dict[byte].append(i)
            else:
                c.dict[byte] = [i]
        else:
            c.result = i
    for byte in c.dict:
        c.dict[byte] = build_catalog(c.dict[byte], index+1, base+byte)
    return c


def get_leaf(c):
    if c.result:
        return c.result
    return get_leaf(list(c.dict.values())[0])


def build_text_catalog(c, index=0, text=[], lookup={}):
    if c.count > 1:
        lookup[len(text)] = c

        suffix = ".." * (min(c.lengths) - len(c.base)//2) + " " +\
            ".." * (max(c.lengths) - min(c.lengths))
        text.append("  "*index+"> "+c.base+suffix)
        if not c.collapsed:
            if c.result:
                lookup[len(text)] = c.result
                text.append("  "*index+"  "+hexlify(c.result.raw).decode())
            for b in sorted(c.dict):
                build_text_catalog(c.dict[b], index+1, text, lookup)
    else:
        i = get_leaf(c)
        lookup[len(text)] = i
        text.append("  "*index+hexlify(i.raw).decode())

    return text, lookup


class Gui:
    BLACK = 1
    WHITE = 2
    BLUE = 3
    RED = 4
    GREEN = 5

    COLOR_BLACK = 16
    COLOR_WHITE = 17
    COLOR_BLUE = 18
    COLOR_RED = 19
    COLOR_GREEN = 20

    GRAY_BASE = 50
    GRAYS = 50

    def __init__(self, summary):
        self.S = summary
        self.running = True
        self.selected = 0

        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        self.stdscr.keypad(True)

        self.init_colors()

        self.stdscr.bkgd(curses.color_pair(self.WHITE))

    def init_colors(self):
        if curses.has_colors() and curses.can_change_color():
            curses.init_color(self.COLOR_BLACK, 0, 0, 0)
            curses.init_color(self.COLOR_WHITE, 1000, 1000, 1000)
            curses.init_color(self.COLOR_BLUE, 0, 0, 1000)
            curses.init_color(self.COLOR_RED, 1000, 0, 0)
            curses.init_color(self.COLOR_GREEN, 0, 1000, 0)

            for i in range(self.GRAYS):
                curses.init_color(
                    self.GRAY_BASE + i,
                    i * 1000 // self.GRAYS,
                    i * 1000 // self.GRAYS,
                    i * 1000 // self.GRAYS
                )
                curses.init_pair(
                    self.GRAY_BASE + i,
                    self.GRAY_BASE + i,
                    self.COLOR_BLACK
                )
        curses.init_pair(self.BLACK, self.COLOR_BLACK, self.COLOR_BLACK)
        curses.init_pair(self.WHITE, self.COLOR_WHITE, self.COLOR_BLACK)
        curses.init_pair(self.BLUE, self.COLOR_BLUE, self.COLOR_BLACK)
        curses.init_pair(self.RED, self.COLOR_RED, self.COLOR_BLACK)
        curses.init_pair(self.GREEN, self.COLOR_GREEN, self.COLOR_BLACK)

    def gray(self, scale):
        return curses.color_pair(self.GRAY_BASE + int(round(scale * (self.GRAYS - 1))))

    def draw_info(self):
        selected = self.S.lookup[self.selected]
        if type(selected) is Catalog:
            y = 0
            x = 50
            self.stdscr.addstr(y, x, "base:", curses.color_pair(self.RED))
            self.stdscr.addstr(y+1, x, selected.base, curses.color_pair(self.WHITE))

            self.stdscr.addstr(y+3, x, "prefixes:", self.gray(0.5))
            self.stdscr.addstr(y+3, x+15, f"({','.join(sorted(selected.prefixes))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+4, x, "valids:", self.gray(0.5))
            self.stdscr.addstr(y+4, x+15, f"({','.join(map(str,selected.valids))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+5, x, "lengths:", self.gray(0.5))
            self.stdscr.addstr(y+5, x+15, f"({','.join(map(str,selected.lengths))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+6, x, "signums:", self.gray(0.5))
            self.stdscr.addstr(y+6, x+15, f"({','.join(map(str,selected.signums))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+7, x, "sicodes:", self.gray(0.5))
            self.stdscr.addstr(y+7, x+15, f"({','.join(map(str,selected.sicodes))})", curses.color_pair(self.WHITE))
        elif type(selected) is Result:
            y = 0
            x = 50
            self.stdscr.addstr(y, x, "instruction:",
                               curses.color_pair(self.RED))
            self.stdscr.addstr(y+1, x, hexlify(selected.raw).decode(), curses.color_pair(self.WHITE))

            self.stdscr.addstr(y+3, x, "prefixes:", self.gray(0.5))
            self.stdscr.addstr(y+3, x+15, f"({','.join(sorted(selected.prefixes))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+4, x, "valids:", self.gray(0.5))
            self.stdscr.addstr(y+4, x+15, f"({','.join(map(str,selected.valids))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+5, x, "lengths:", self.gray(0.5))
            self.stdscr.addstr(y+5, x+15, f"({','.join(map(str,selected.lengths))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+6, x, "disas lengths:", self.gray(0.5))
            self.stdscr.addstr(y+6, x+15, f"({','.join(map(str,selected.dl))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+7, x, "signums:", self.gray(0.5))
            self.stdscr.addstr(y+7, x+15, f"({','.join(map(str,selected.signums))})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+8, x, "signals:", self.gray(0.5))
            self.stdscr.addstr(y+8, x+15, f"({','.join(selected.signals)})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+9, x, "sicodes:", self.gray(0.5))
            self.stdscr.addstr(y+9, x+15, f"({','.join(map(str,selected.sicodes))})", curses.color_pair(self.WHITE))

            self.stdscr.addstr(y+11, x, "disassembly:", curses.color_pair(self.RED))
            self.stdscr.addstr(y+12, x, "capstone:", self.gray(0.5))

            size, mnemonic, op_str = capstone_dissasembler(selected.raw)
            if op_str:
                self.stdscr.addstr(y+13, x, f"\t({mnemonic} {op_str})", curses.color_pair(self.WHITE))
            else:
                self.stdscr.addstr(y+13, x, f"\t({mnemonic})", curses.color_pair(self.WHITE))
            self.stdscr.addstr(y+14, x+2, f"size:  ({size})",self.gray(0.5))

            self.stdscr.addstr(y+16, x, "analysis:", curses.color_pair(self.RED))
            (length,) = selected.lengths
            (dl,) = selected.dl
            analysis = ""
            if size == 0:
                analysis = "Undocumented Instruction"
            elif length != size:
                analysis = "Software Bug"
            elif dl == 0:
                analysis = "Previously Undocumented Instruction"
            elif length != dl:
                analysis = "Old Software Bug"
            else:
                analysis = "??"
            self.stdscr.addstr(y+17, x+2, analysis, curses.color_pair(self.WHITE))

    def render(self):
        while self.running:
            try:
                self.stdscr.erase()
                for l, i in enumerate(self.S.text):
                    start = self.selected-self.stdscr.getmaxyx()[0]//2+1
                    if(start > l):
                        continue
                    if(l-max(0, start) >= self.stdscr.getmaxyx()[0]):
                        break
                    if self.selected == l:
                        self.stdscr.addstr(
                            l-max(0, start), 0, i, curses.color_pair(self.RED))
                    else:
                        self.stdscr.addstr(
                            l-max(0, start), 0, i, curses.color_pair(self.WHITE))
                self.draw_info()
                self.stdscr.refresh()
            except curses.error:
                pass

            self.check_key()
            time.sleep(.01)

    def check_key(self):
        c = self.stdscr.getch()
        if c == ord("q"):
            self.running = False
        if c == curses.KEY_UP:
            self.selected = max(0, self.selected-1)
        if c == curses.KEY_DOWN:
            self.selected = min(len(self.S.text)-1, self.selected+1)
        if c == curses.KEY_ENTER or c == ord("\n"):
            if type(self.S.lookup[self.selected]) is Catalog:
                self.S.lookup[self.selected].collapsed = not self.S.lookup[self.selected].collapsed
                self.S.text, self.S.lookup = build_text_catalog(
                    self.S.catalog, 0, [], {})


def merge_sets(instructions, attr):
    s = set()
    for i in instructions:
        s |= getattr(i, attr)
    return s


def strip_prefixes(raw):
    while is_prefix(raw[0]):
        raw = raw[1:]
    return bytes(raw)


def get_prefixes(raw):
    prefixes = []
    for x in raw:
        if not is_prefix(x):
            break
        prefixes.append(hex(x))
    return sorted(prefixes)


def is_prefix(x):
    return x == 0xf0 or\
        x == 0xf2 or\
        x == 0xf3 or\
        x == 0x2e or\
        x == 0x36 or\
        x == 0x3e or\
        x == 0x26 or\
        x == 0x64 or\
        x == 0x65 or\
        x == 0x2e or\
        x == 0x3e or\
        x == 0x66 or\
        x == 0x67 or\
        (x >= 0x40 and x <= 0x4f)


def main():
    summary = Summary()
    summary.summarize()

    gui = Gui(summary)
    gui.render()

    curses.nocbreak()
    curses.curs_set(1)
    curses.echo()
    curses.endwin()


if __name__ == "__main__":
    main()
