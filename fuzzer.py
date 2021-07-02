import subprocess
import time
import curses
import os
from threading import Thread
from collections import deque
from ctypes import *
from capstone import *
from binascii import hexlify
import copy


INJECTOR = "./injector"


OUTPUT = "./data/"
LOG = OUTPUT + "log"

class State:
    running = True
    paused = False


class InjectorResults(Structure):
    _fields_ = [("disas_len", c_int),
                ("valid", c_int),
                ("len", c_int),
                ("signum", c_int),
                ("si_code", c_int),
                ("addr", c_uint32),
                ("raw_ins", c_ubyte*16)]


class Summery:
    result = InjectorResults()
    IL = 20
    AL = 10
    instructions = deque(maxlen=IL)
    anomalies = deque(maxlen=AL)
    count_anomalies = 0
    count_instructions = 0
    ad = {}


class Injector:

    def __init__(self, state):
        self.command = None
        self.process = None
        self.state = state

    def start(self):
        self.command = f"{INJECTOR}"
        self.process = subprocess.Popen([self.command], shell=True, stdout=subprocess.PIPE)

    def stop(self):
        self.process.terminate()


class Sifter:
    SIGILL = 4
    ILL_ILLOPC = 1
    ILL_ILLOPN = 2

    def __init__(self, injector, summery, state):
        self.injector = injector
        self.S = summery
        self.state = state
        self.sifter_thread = None

    def start(self):
        self.sifter_thread = Thread(target=self.sift)
        self.sifter_thread.start()

    def stop(self):
        self.sifter_thread.join()

    def sift(self):
        while self.state.running:
            while self.state.paused:
                time.sleep(.1)

            bytes_polled = self.injector.process.stdout.readinto(self.S.result)
            if bytes_polled == sizeof(self.S.result):
                anomaly = False
                UD = self.S.result.si_code == self.ILL_ILLOPC or self.S.result.si_code == self.ILL_ILLOPN
                if not self.S.result.valid and (self.S.result.signum != self.SIGILL or not UD):
                    anomaly = True
                if self.S.result.disas_len != self.S.result.len and self.S.result.signum != self.SIGILL:
                    anomaly = True

                if anomaly:
                    self.S.anomalies.append(
                        (hexlify(self.S.result.raw_ins), self.S.result.len))
                    self.S.ad[hexlify(self.S.result.raw_ins)] = copy.deepcopy(self.S.result)
                    self.S.count_anomalies += 1
                self.S.count_instructions += 1
            else:
                if self.injector.process.poll() is not None:
                    self.state.running = False


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

    def __init__(self, summery, state, disassmebler):
        self.S = summery
        self.state = state
        self.gui_thread = None
        self.disassemble = disassmebler

        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        self.stdscr.nodelay(True)

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

    def start(self):
        self.gui_thread = Thread(target=self.render)
        self.gui_thread.start()

    def stop(self):
        self.gui_thread.join()

    def draw(self):

        try:
            self.stdscr.erase()
            top = 1
            left = 1

            size, mnemonic, op_str = self.disassemble(self.S.result.raw_ins)
            self.S.instructions.append(
                (size,
                 mnemonic,
                 op_str,
                 self.S.result.len,
                 hexlify(self.S.result.raw_ins))
            )

            try:
                for i, r in enumerate(self.S.instructions):
                    size, mnemonic, op_str, length, raw = r
                    if i == len(self.S.instructions) - 1:
                        self.stdscr.addstr(
                            top + i, left, mnemonic, curses.color_pair(self.WHITE))
                        self.stdscr.addstr(
                            top + i, left + 11, op_str,  curses.color_pair(self.BLUE))
                        self.stdscr.addstr(
                            top + i, left + 11 + 45, raw[:length*2], curses.color_pair(self.WHITE))
                        self.stdscr.addstr(
                            top + i, left + 11 + 45 + length*2, raw[length*2:-2], self.gray(0.5))
                    else:
                        self.stdscr.addstr(
                            top + i, left, mnemonic, self.gray(0.5))
                        self.stdscr.addstr(
                            top + i, left + 11, op_str,  self.gray(0.5))
                        self.stdscr.addstr(
                            top + i, left + 11 + 45, raw[:length*2], self.gray(0.5))
                        self.stdscr.addstr(
                            top + i, left + 11 + 45 + length*2, raw[length*2:-2], self.gray(0.1))
            except RuntimeError:
                pass

            self.stdscr.addstr(top + 26, left, "#", self.gray(0.5))
            self.stdscr.addstr(top + 26, left + 2, f"{self.S.count_instructions}", curses.color_pair(self.WHITE))
              
            self.stdscr.addstr(top + 28, left, "#", self.gray(0.5))
            self.stdscr.addstr(top + 28, left + 2, f"{self.S.count_anomalies}", curses.color_pair(self.RED))
                
            try:
                for i, r in enumerate(self.S.anomalies):
                    line = self.S.AL - i - 1
                    raw, length = r
                    self.stdscr.addstr(top + line + 30, left, raw[0:length*2],
                                       curses.color_pair(self.RED))
                    self.stdscr.addstr(top + line + 30, left + length*2,
                                       raw[length*2:-2], self.gray(0.3))
            except RuntimeError:
                pass

            self.stdscr.refresh()
        except curses.error:
            pass

    def render(self):
        while self.state.running:
            while self.state.paused:
                self.check_key()

            self.check_key()

            self.draw()

            time.sleep(.01)

    def check_key(self):
        c = self.stdscr.getch()
        if c == ord("p"):
            self.state.paused = not self.state.paused
        elif c == ord("q"):
            self.state.running = False
            self.state.paused = False


def capstone_dissasembler(raw_ins):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for (address, size, mnemonic, op_str) in md.disasm_lite(bytes(raw_ins), 0x0000):
        return size, mnemonic, op_str
    return 0, "Unknown", ""


def cleanup(state, injector, sifter, gui, summery):
    state.running = False
    if injector:
        injector.stop()
    if sifter:
        sifter.stop()
    if gui:
        gui.stop()

    dump_anomalies(summery)

    curses.nocbreak()
    curses.curs_set(1)
    curses.echo()
    curses.endwin()

def dump_anomalies(summery):
    if not os.path.exists(OUTPUT):
        os.mkdir(OUTPUT)
    with open(LOG, "wb") as f:
        for k in sorted(list(summery.ad)):
            f.write(summery.ad[k])


def main():
    state = State()

    injector = Injector(state)
    injector.start()

    summery = Summery()

    sifter = Sifter(injector, summery, state)
    sifter.start()

    gui = Gui(summery, state, capstone_dissasembler)
    gui.start()

    while state.running:
        time.sleep(.1)

    cleanup(state, injector, sifter, gui, summery)


if __name__ == "__main__":
    main()