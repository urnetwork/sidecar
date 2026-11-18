"""Assemble DESIGN-DEFER.md from defer/ and check it against the section files (owner decision 587).

Usage: python3 -I defer10.py <design_dir> <asm_dir> <defer_md>
Writes <defer_md> and <asm_dir>/v7/defer.json, prints a summary, and exits 1 when an entry is malformed, an anchor
repeats, a link to an entry does not resolve, an entry has no pointer in the section files, or an entry cites an R-,
D- or Q- item or a subsection the section files do not hold.

defer/00-INTRO.md is the document's opening, copied verbatim. defer/NN-CODE.md holds §NN's entries, named as
sections/NN-CODE.md is. An entry is:

    ### <anchor>: <title>
    Stage: <Later | v1 (M6) | ...>
    - **Deferred:** what, with its ids
    - **Why:** ...
    - **Launch instead:** ...
    - **Lost:** ...
    - **Dark in code:** ...
    - **Held:** ...
    - **To bring back:** ...

The seven fields come in that order, each one line. A section points at an entry with a link to
DESIGN-DEFER.md#<anchor>, or inside a code fence, where a link does not render, with the words "DESIGN-DEFER.md's
<anchor> entry"; the index and each entry's head list the subsections that do.
"""
import json, pathlib, re, sys

design = pathlib.Path(sys.argv[1]); asm = pathlib.Path(sys.argv[2]); out_path = pathlib.Path(sys.argv[3])
FIELDS = ['Deferred', 'Why', 'Launch instead', 'Lost', 'Dark in code', 'Held', 'To bring back']
ANCHOR = re.compile(r'^[a-z][a-z0-9]*(-[a-z0-9]+)+$')
LINK = re.compile(r"\]\(DESIGN-DEFER\.md#([^)\s]+)\)|DESIGN-DEFER\.md's ([a-z0-9-]+) entry")
errors = []

# ---------------------------------------------------------------- the sections: titles and pointers
titles = {}      # section number -> its "## N. Title" text
items = set()    # every R-, D- and Q- id the sections name
subsections = set()   # every "N.M" a section heading opens
pointers = {}    # anchor -> ordered list of subsections ("8.8") whose text links it
section_files = sorted((design / 'sections').glob('*.md'), key=lambda p: int(p.name.split('-')[0]))
for f in section_files:
    num = int(f.name.split('-')[0])
    here = str(num)
    items.update(re.findall(r'\b[RDQ]-[A-Z]+-\d+\b', f.read_text()))
    for line in f.read_text().split('\n'):
        m = re.match(r'^## (\d+)\. (.+)$', line)
        if m and int(m.group(1)) == num:
            titles[num] = m.group(2)
        m = re.match(r'^### (\d+\.\d+) ', line)
        if m:
            here = m.group(1)
            subsections.add(here)
        for anchor in (a or b for a, b in LINK.findall(line)):
            seen = pointers.setdefault(anchor, [])
            if here not in seen:
                seen.append(here)

# ---------------------------------------------------------------- the entries
groups = []      # (section number, [entry])
anchors = {}
for f in sorted((design / 'defer').glob('*.md')):
    num = int(f.name.split('-')[0])
    if num == 0:
        continue
    if not (design / 'sections' / f.name).exists():
        errors.append(f'{f.name}: no section file of that name')
    entries = []; entry = None
    for n, line in enumerate(f.read_text().split('\n'), 1):
        where = f'{f.name}:{n}'
        if line.startswith('### '):
            m = re.match(r'^### ([^:\s]+): (.+)$', line)
            if not m or not ANCHOR.match(m.group(1)):
                errors.append(f'{where}: an entry opens "### <anchor>: <title>", the anchor lowercase words joined by hyphens')
                entry = None
                continue
            entry = {'anchor': m.group(1), 'title': m.group(2).strip(), 'stage': None, 'fields': [], 'file': f.name, 'line': n}
            if entry['anchor'] in anchors:
                errors.append(f'{where}: anchor {entry["anchor"]} repeats {anchors[entry["anchor"]]}')
            anchors[entry['anchor']] = where
            entries.append(entry)
        elif not line.strip():
            continue
        elif entry is None:
            errors.append(f'{where}: text outside an entry')
        elif line.startswith('Stage: ') and entry['stage'] is None and not entry['fields']:
            entry['stage'] = line[len('Stage: '):].strip()
        else:
            m = re.match(r'^- \*\*([^*]+):\*\* (\S.*)$', line)
            if not m:
                errors.append(f'{where}: an entry holds its Stage line and seven "- **Field:** text" lines, nothing else')
                continue
            entry['fields'].append((m.group(1), m.group(2).strip()))
    for entry in entries:
        where = f'{entry["file"]}:{entry["line"]}'
        if not entry['stage']:
            errors.append(f'{where}: {entry["anchor"]} has no Stage line')
        if [name for name, text in entry['fields']] != FIELDS:
            errors.append(f'{where}: {entry["anchor"]} must give, in order: {", ".join(FIELDS)}')
        body = ' '.join(text for name, text in entry['fields'])
        for cited_id in sorted(set(re.findall(r'\b[RDQ]-[A-Z]+-\d+\b', body)) - items):
            errors.append(f'{where}: {entry["anchor"]} cites {cited_id}, which no section names')
        for sub in sorted(set(re.findall(r'§(\d+\.\d+)', body)) - subsections):
            errors.append(f'{where}: {entry["anchor"]} cites §{sub}, which no section holds')
    groups.append((num, entries))

unresolved = sorted(a for a in pointers if a not in anchors)
for a in unresolved:
    errors.append(f'sections link DESIGN-DEFER.md#{a} (§{", §".join(pointers[a])}), which no entry defines')
unpointed = sorted(e['anchor'] for num, entries in groups for e in entries if e['anchor'] not in pointers)
for a in unpointed:
    errors.append(f'entry {a} ({anchors[a]}) has no pointer: no section links DESIGN-DEFER.md#{a}')

# ---------------------------------------------------------------- the document
def cited(anchor):
    return ', '.join('§' + s for s in pointers.get(anchor, [])) or 'no section'

intro = (design / 'defer' / '00-INTRO.md').read_text().strip('\n')
count = sum(len(entries) for num, entries in groups)
doc = [intro, '', '## Index', '',
       f'{count} entries, grouped by the DESIGN.md section that owns the deferred thing. "Described in" lists the '
       'subsections of DESIGN.md that point at the entry.', '',
       '| Section | Entry | Stage | Described in |', '|---|---|---|---|']
for num, entries in groups:
    for i, e in enumerate(entries):
        sec = f'[§{num} {titles.get(num, "")}](#s{num})' if i == 0 else ''
        doc.append(f'| {sec} | [{e["title"]}](#{e["anchor"]}) | {e["stage"]} | {cited(e["anchor"])} |')
for num, entries in groups:
    if not entries:
        continue
    doc += ['', f'<a id="s{num}"></a>', f'## §{num} {titles.get(num, "")}']
    for e in entries:
        doc += ['', f'<a id="{e["anchor"]}"></a>', f'### {e["title"]}', '',
                f'*{e["stage"]}. DESIGN.md: {cited(e["anchor"])}.*', '']
        doc += [f'- **{name}.** {text}' for name, text in e['fields']]
text = '\n'.join(doc) + '\n'

own_anchors = set(anchors) | {f's{num}' for num, entries in groups if entries}
own_missing = sorted(set(a for a in re.findall(r'\]\(#([^)\s]+)\)', text) if a not in own_anchors))
for a in own_missing:
    errors.append(f'DESIGN-DEFER.md links #{a}, which it does not define')
relative = sorted(set(r.split('#')[0] for r in re.findall(r'\]\(((?!#|https?:)[^)\s]+)\)', text)))
# DESIGN.md is written beside this file by the same build, so a link to it is checked by name only.
relative_missing = [r for r in relative if r != 'DESIGN.md' and not (design.parent.parent / r).exists()]
for r in relative_missing:
    errors.append(f'DESIGN-DEFER.md links {r}, which the checkout does not hold')

summary = {'entries': count, 'groups': {str(num): len(entries) for num, entries in groups if entries},
           'stages': {}, 'pointers': sum(len(v) for v in pointers.values()), 'pointed_entries': len([a for a in anchors if a in pointers]),
           'unresolved_pointers': unresolved, 'unpointed_entries': unpointed, 'own_links_missing': own_missing,
           'relative_links_missing': relative_missing, 'words': len(text.split()), 'errors': errors}
for num, entries in groups:
    for e in entries:
        key = (e['stage'] or '').split(',')[0].split(' (')[0]
        summary['stages'][key] = summary['stages'].get(key, 0) + 1
(asm / 'v7' / 'defer.json').write_text(json.dumps(summary, indent=1, ensure_ascii=False))
print(json.dumps(summary, indent=1, ensure_ascii=False))
if errors:
    sys.exit(1)
out_path.write_text(text)
