"""Render the ethical statement and technical NOTICE consistently; no network access."""
import argparse
import html
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- operator-notice:start -->'
END = '<!-- operator-notice:end -->'
SOURCE = 'https://phishdestroy.io/steam_dossier/taylor_wessing'


def statement(root):
    source = (root / 'NOTICE').read_text(encoding='utf-8')
    parts = source.split('=' * 64)
    if len(parts) != 4 or parts[1].strip() != 'NOTICE — Operator Incompatibility':
        raise ValueError('NOTICE must contain the named statement between its original separators')
    return parts[2].strip()


def quoted_html(text):
    """Preserve wording; use paragraphs and lists instead of a fixed-width text box."""
    blocks = []
    for paragraph in re.split(r'\n\s*\n', text):
        lines = paragraph.splitlines()
        if any(line.lstrip().startswith('—  ') for line in lines):
            title, entries = [], []
            for line in lines:
                if line.lstrip().startswith('—  '):
                    entries.append(line.lstrip()[3:].strip())
                elif entries:
                    entries[-1] += ' ' + line.strip()
                else:
                    title.append(line.strip())
            blocks.append('<p>' + html.escape(' '.join(title)) + '</p>')
            blocks.append('<ul>' + ''.join('<li>' + html.escape(item) + '</li>' for item in entries) + '</ul>')
        elif lines[0].strip() == 'Including, without limitation:':
            blocks.append('<p>Including, without limitation:</p>')
            blocks.append('<ul>' + ''.join('<li>' + html.escape(' '.join(line.split())) + '</li>' for line in lines[1:]) + '</ul>')
        else:
            blocks.append('<p>' + html.escape(' '.join(line.strip() for line in lines)) + '</p>')
    return '<blockquote>\n' + '\n'.join(blocks) + '\n</blockquote>'


def ethical_excerpt(ethical):
    heading, body = ethical.split('\n', 1)
    title = html.escape(heading.removeprefix('## '))
    return f'''<details>
<summary><strong>{title}</strong></summary>

{body.strip()}

[Source record]({SOURCE})

[MIT License](LICENSE) · [Technical notice](docs/OPERATOR-INCOMPATIBILITY.md) · [Original NOTICE](NOTICE)

</details>'''


def excerpt(notice, licence, raw):
    return f"[Author's position]({notice}) · [Source record]({SOURCE}) · [MIT License]({licence})\n"


def document(ethical, *, wiki=False):
    prefix = '../' if wiki else ''
    root = '../../' if wiki else '../'
    return f'''# NOTICE — Operator Incompatibility

**PhishDestroy · TgWitness project notice**

[Source record]({SOURCE}) · [Original NOTICE]({root}NOTICE)

{ethical}

[MIT License]({root}LICENSE) · [Our position on Taylor Wessing]({prefix}TAYLOR-WESSING-EXCLUSION.md) · [Evidence model]({prefix}HOW-IT-WORKS.md)

[Project]({root}README.md) · [Documentation]({prefix}README.md) · [Wiki]({'Home.md' if wiki else 'wiki/Home.md'})
'''


def licence_document(full):
    return f'''# Licence and Architectural Incompatibility Notice

TgWitness is distributed under the [MIT License](../LICENSE). Our position adds no licence condition.

{full}

[Source record]({SOURCE}) · [Ethical Notice & Historical Continuity](OPERATOR-INCOMPATIBILITY.md)

[Full MIT Licence](../LICENSE) · [Project](../README.md) · [Documentation](README.md) · [Wiki](wiki/Home.md)
'''


def outputs(root):
    full = quoted_html(statement(root))
    ethical = (root / 'docs/ETHICAL-NOTICE.md').read_text(encoding='utf-8').strip()
    if not ethical.startswith('## ⚖️ Ethical Notice & Historical Continuity\n'):
        raise ValueError('The ethical statement must start with its named heading')
    result = {
        'docs/OPERATOR-INCOMPATIBILITY.md': document(ethical),
        'docs/TAYLOR-WESSING-EXCLUSION.md': licence_document(full),
        'docs/wiki/Operator-Incompatibility.md': ethical + f'''

[Source record]({SOURCE})

---

[MIT License](../../LICENSE) · [Technical notice](../OPERATOR-INCOMPATIBILITY.md) · [Original NOTICE](../../NOTICE)

[Project](../../README.md) · [Documentation](../README.md) · [Wiki](Home.md)
''',
    }
    for name, notice, licence, raw in (
        ('README.md', 'docs/OPERATOR-INCOMPATIBILITY.md', 'LICENSE', 'NOTICE'),
        ('.github/SECURITY.md', '../docs/OPERATOR-INCOMPATIBILITY.md', '../LICENSE', '../NOTICE'),
    ):
        source = (root / name).read_text(encoding='utf-8')
        if source.count(START) != 1 or source.count(END) != 1:
            raise ValueError('Exactly one notice slot is required in ' + name)
        before, tail = source.split(START, 1)
        _, after = tail.split(END, 1)
        content = ethical_excerpt(ethical) if name == 'README.md' else excerpt(notice, licence, raw)
        result[name] = before + START + '\n\n' + content + '\n\n' + END + after
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    stale = []
    for name, text in outputs(ROOT).items():
        path = ROOT / name
        if path.exists() and path.read_text(encoding='utf-8') == text:
            continue
        if args.check:
            stale.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
    if stale:
        parser.exit(1, 'NOTICE copies need regeneration: ' + ', '.join(stale) + '\n')
    print('NOTICE copies are consistent.' if args.check else 'Updated NOTICE in README, SECURITY, documentation and Wiki.')


if __name__ == '__main__':
    main()
