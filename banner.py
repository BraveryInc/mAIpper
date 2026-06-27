#!/usr/bin/env python3
"""
mAIpper startup banner v2 — clean ANSI treasure map.
Islands float in a sea of ≈ with just their landmark names.

Usage:
    from maipper_banner import print_banner
    print_banner()

Compatibility:
    Linux / macOS  : any modern terminal emulator (102+ cols)
    Windows        : Windows Terminal (Win10+) native; cmd.exe
                     needs  os.system('')  first to enable ANSI.
    Optional       : pip install pyfiglet  -> upgrades title to doom font
"""

import re
import sys

G   = '\033[33m'    # gold / amber
BG  = '\033[93m'    # bright gold
R   = '\033[91m'    # red
CY  = '\033[36m'    # cyan  (water)
DIM = '\033[2m'
BD  = '\033[1m'
RS  = '\033[0m'

def _g(t):   return f"{G}{t}{RS}"
def _bg(t):  return f"{BG}{BD}{t}{RS}"
def _r(t):   return f"{R}{t}{RS}"
def _cy(t):  return f"{CY}{t}{RS}"
def _dim(t): return f"{DIM}{G}{t}{RS}"

_RE = re.compile(r'\033\[[0-9;]*m')

def _vis(s):
    return len(_RE.sub('', s))

def _pad(s, w, c=' '):
    return s + c * max(0, w - _vis(s))

INNER = 100

def _row(content):
    return _g('║') + _pad(content, INNER) + _g('║')

_TITLE = [
    r"  __  __   /\    ___  ____   ____  _____  ____  ",
    r" |  \/  | /  \  |_ _||  _ \ |  _ \| ____||  _ \ ",
    r" | |\/| |/ /\ \  | | | |_) || |_) ||  _|  | |_) |",
    r" |_|  |_/_/  \_\|___|____/  |____/ |_____|____/  ",
]

def _get_title():
    try:
        import pyfiglet
        raw   = pyfiglet.figlet_format('MAIPPER', font='doom').split('\n')
        lines = [l for l in raw if l.strip()][:4]
        while len(lines) < 4:
            lines.append('')
        return lines
    except Exception:
        return list(_TITLE)


def _isle(col, row, n1, n2, w, nfn=None, bfn=None, bc='~', oc='(', cc=')'):
    """
    4-line island fragment: top border, name-line-1, name-line-2, bottom border.
    Returns list of (map_row, col, text, color_fn).
    """
    nfn = nfn or _bg
    bfn = bfn or _g
    inner = w - 2
    return [
        (row,   col, '.' + bc * inner + '.',  bfn),
        (row+1, col, oc + n1.center(inner) + cc, nfn),
        (row+2, col, oc + n2.center(inner) + cc, nfn),
        (row+3, col, "'" + bc * inner + "'", bfn),
    ]


def _sea_row(overlays):
    """
    Build a 100-char cyan sea row with gold island text overlaid.
    overlays: list of (col, text, color_fn), sorted by col.
    """
    parts = []
    pos   = 0
    for col, text, fn in sorted(overlays, key=lambda x: x[0]):
        if col > pos:
            parts.append(_cy('≈' * (col - pos)))
        parts.append(fn(text))
        pos = col + len(text)
    if pos < INNER:
        parts.append(_cy('≈' * (INNER - pos)))
    return _row(''.join(parts))


def print_banner():
    if sys.platform == 'win32':
        import os; os.system('')

    out   = []
    a     = out.append
    title = _get_title()

    # ── header ───────────────────────────────────────────────────────────────
    a(_g('╔' + '═' * INNER + '╗'))
    a(_row(_cy('≈' * INNER)))

    for tl in title:
        tp = (INNER - len(tl)) // 2
        a(_row(' ' * tp + _bg(tl)))

    sub = (_dim('─── ') + _r('(X)') + _dim(' ───  ')
           + _bg('  by Bravery Inc.  ')
           + _dim('  ─── ') + _r('(X)') + _dim(' ───'))
    sp = (INNER - _vis(sub)) // 2
    a(_row(' ' * sp + sub))
    a(_row(_cy('≈' * INNER)))

    # ── map ──────────────────────────────────────────────────────────────────
    # Layout (all positions verified non-overlapping per row):
    #
    # Rows 0-3  : SEA OF RECON(col 1, w14)  ANALYSIS ISLAND(col 39, w14)
    #             VULNERABILITY SHOALS(col 60, w18)
    # Rows 2-5  : ENUMERATION STRAIT(col 19, w16)  EXPLOITATION REEF(col 82, w16)
    # Row  6    : ≈ water + X marker (col 49)
    # Rows 7-10 : PRIV-ESC PEAKS(col 38, w14)  LATERAL LAGOON(col 61, w14)
    # Rows 11-14: THE UNKNOWN DEPTHS(col 1, w18)  TREASURE COVE(col 65, w14)
    # Rows 12-15: DEAD SCANS SHOALS(col 23, w16)
    # Rows 13-16: OBSIDIAN VAULT(col 82, w14)

    frags = []
    ext   = frags.extend

    ext(_isle( 1,  0, 'SEA OF',        'RECON',        14))
    ext(_isle(39,  0, 'ANALYSIS',       'ISLAND',       14))
    ext(_isle(60,  0, 'VULNERABILITY',  'SHOALS',       18))
    ext(_isle(19,  2, 'ENUMERATION',    'STRAIT',       16))
    ext(_isle(82,  2, 'EXPLOITATION',   'REEF',         16))

    frags.append((6, 49, 'X', _r))                          # treasure X

    ext(_isle(38,  7, 'PRIV-ESC',      'PEAKS',        14))
    ext(_isle(61,  7, 'LATERAL',        'LAGOON',       14))

    ext(_isle( 1, 11, 'THE UNKNOWN',    'DEPTHS',       18, nfn=_dim, bfn=_dim))
    ext(_isle(65, 11, 'TREASURE',       'COVE',         14))
    ext(_isle(23, 12, 'DEAD SCANS',     'SHOALS',       16, nfn=_dim, bfn=_dim))
    ext(_isle(82, 13, 'OBSIDIAN',       'VAULT',        14, bc='=', oc='[', cc=']'))

    MAP_H    = 18
    map_rows = [[] for _ in range(MAP_H)]
    for r, c, text, fn in frags:
        if 0 <= r < MAP_H:
            map_rows[r].append((c, text, fn))

    for mr in map_rows:
        a(_sea_row(mr))

    # ── footer ───────────────────────────────────────────────────────────────
    a(_row(_cy('≈' * INNER)))
    quote = (_bg('"A good map turns chaos into conquest."')
             + _dim('  ─── mAIpper'))
    qp = (INNER - _vis(quote)) // 2
    a(_row(' ' * qp + quote))
    a(_row(_cy('≈' * INNER)))
    a(_g('╚' + '═' * INNER + '╝'))

    print('\n'.join(out))


if __name__ == '__main__':
    print_banner()