"""Shared helpers for the DESIGN.md assembly scripts. Loaded with runpy.run_path (scripts run under python3 -I)."""
import re

HEAD_RE = re.compile(r'^(#{1,6})\s+(.*?)\s*$')
R_CITE = re.compile(r'\[R:([a-z0-9-]+)\](?!\()')


def code_mask(lines):
    """True for lines inside fenced code blocks (``` or ~~~), fences included."""
    mask = [False] * len(lines)
    infence, mark = False, None
    for k, l in enumerate(lines):
        s = l.lstrip()
        if not infence and (s.startswith('```') or s.startswith('~~~')):
            infence, mark = True, s[:3]
            mask[k] = True
            continue
        if infence:
            mask[k] = True
            if s.startswith(mark):
                infence = False
    return mask


def slugify(text):
    """GitHub-style heading anchor."""
    t = re.sub(r'`([^`]*)`', r'\1', text)
    t = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', t)
    t = re.sub(r'\*\*(.*?)\*\*', r'\1', t)
    t = t.strip().lower()
    t = ''.join(ch for ch in t if ch.isalnum() or ch in '-_ ')
    return t.replace(' ', '-')


class Slugger:
    def __init__(self):
        self.seen = {}

    def slug(self, text):
        base = slugify(text)
        if base in self.seen:
            self.seen[base] += 1
            return f"{base}-{self.seen[base]}"
        self.seen[base] = 0
        return base


def headings(text):
    """(line index, level, title) for every Markdown heading outside fenced code."""
    lines = text.split('\n')
    mask = code_mask(lines)
    out = []
    for k, l in enumerate(lines):
        if mask[k]:
            continue
        m = HEAD_RE.match(l)
        if m:
            out.append((k, len(m.group(1)), m.group(2)))
    return out


def convert_r_links(line, research_rel, counter=None):
    """[R:key] -> [R:key](research_rel/key.md), skipping inline code spans."""
    parts = re.split(r'(`[^`]*`)', line)
    for i, p in enumerate(parts):
        if p.startswith('`') and p.endswith('`') and len(p) >= 2:
            continue

        def rep(m):
            if counter is not None:
                counter[0] += 1
            return f"[R:{m.group(1)}]({research_rel}/{m.group(1)}.md)"
        parts[i] = R_CITE.sub(rep, p)
    return ''.join(parts)


def convert_text(text, research_rel):
    lines = text.split('\n')
    mask = code_mask(lines)
    for k, l in enumerate(lines):
        if not mask[k]:
            lines[k] = convert_r_links(l, research_rel)
    return '\n'.join(lines)


INLINE_DECIDED = re.compile(r'\*Decided by owner|settled by owner decision|\*Moot \(owner decision')


def q_status(item, qstale=None):
    """Status of a Q- item from its section text: open, decided, withdrawn or closed.
    qstale lists items the owner's record decides although the section still presents them as open."""
    lab, text = item['label'], item['text']
    if 'withdrawn' in lab:
        return 'withdrawn'
    if 'closed by peer review' in lab:
        return 'closed'
    if 'decided' in lab or INLINE_DECIDED.search(text):
        return 'decided'
    if qstale and item['id'] in qstale:
        return 'decided'
    return 'open'


def prefix_status(cell):
    if cell.startswith('**Open.**'):
        return 'open'
    if cell.startswith('Decided ('):
        return 'decided'
    if cell.startswith('Withdrawn:'):
        return 'withdrawn'
    if cell.startswith('Closed by peer review:'):
        return 'closed'
    return None


def norm_decider(raw, status):
    if status == 'withdrawn':
        return '—'
    if status == 'closed':
        return 'peer review'
    if status == 'decided':
        return 'owner'
    raw = (raw or '').strip()
    if raw.startswith('owner'):
        return 'owner'
    if raw.startswith('peer review'):
        return 'peer review'
    return raw or '—'


def words(s):
    return len(s.split())
