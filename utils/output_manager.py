import os
import sys

# Unter Windows: Versuche, den virtuellen Terminal-Modus zu aktivieren (benötigt für ANSI-Farbcodes)
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # STD_OUTPUT_HANDLE = -11
        hStdOut = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(hStdOut, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            new_mode = mode.value | 0x0004
            kernel32.SetConsoleMode(hStdOut, new_mode)
    except Exception:
        pass

# Standard-Handles und Konstanten
_DEVNULL = open(os.devnull, "w")
_ORIG_STDOUT = sys.stdout
_CLEAR_LINE = "\x1b[1A\x1b[2K"  # Kann je nach Windows-Terminal variieren
DELIM = 80 * "="

# ANSI-Farbcodes
RESET = '\033[0m'
BOLD = '\033[1m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = "\033[1;33m"
BLUE = '\033[34m'

def invalidate_print():
    global _DEVNULL
    sys.stdout = _DEVNULL

def restore_print():
    global _ORIG_STDOUT
    sys.stdout = _ORIG_STDOUT

def printf(text, end="\n"):
    global _ORIG_STDOUT, _DEVNULL
    sys.stdout = _ORIG_STDOUT
    print(text, end=end)
    sys.stdout = _DEVNULL

def clear_line(lines=1):
    # Achtung: Das Löschen von Zeilen mit ANSI-Codes funktioniert nicht in allen Windows-Terminals.
    printf(lines * _CLEAR_LINE)

def print_error(text):
    printf(f"[{BOLD}{RED}!{RESET}] {text}")

def print_info(text, end="\n"):
    printf(f"[{BOLD}{BLUE}*{RESET}] {text}", end=end)

def print_input(text):
    # Hier wird der Prompt vorab ausgegeben – input() erhält dann keinen eigenen Text.
    printf(f"[{BOLD}{GREEN}<{RESET}] {text} ")
    return input()

def print_cmd(text):
    printf(f"[{BOLD}{GREEN}>{RESET}] {text}")

def print_debug(text):
    printf(f"[{BOLD}{YELLOW}~{RESET}] {text}")

BANNER = f"""
{BOLD}{RED} __      __ {RESET}__  _____ __         {BOLD}{RED}_________{RESET}                         __   __     
{BOLD}{RED}/  \    /  \\{RESET}__|/ ____\__|        {BOLD}{RED}\    __  \\{RESET}  _____ ______   __ ___/  |_|  |__  
{BOLD}{RED}\   \/\/   /{RESET}  \   __\|  |  ______ {BOLD}{RED}|  |  \  \\{RESET}/ ___ \\\  __ \ |  |  \   __|  |  \\ 
{BOLD}{RED} \        /{RESET}|  ||  |  |  | /_____/ {BOLD}{RED}|  |__/  /{RESET}\  ___/| |__\ \|  |  /|  | |   Y  \\
{BOLD}{RED}  \__/\__/ {RESET}|__||__|  |__|        {BOLD}{RED} |_______/{RESET}  \____/|______/ ____/ |__| |___|__/ 
"""
