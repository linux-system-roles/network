#!/usr/bin/env python3
"""Convert the Sphinx-rendered role HTML page into README.md.

README.md is the role's *main* README. It is what people read directly in the
repository as plain text, and what Markdown viewers render: GitHub, Ansible
Galaxy, and Red Hat Automation Hub (the last two display role documentation only
as Markdown). The content is authored once in meta/argument_specs.yml;
.build_docs.sh renders it to HTML (via antsibull-docs + Sphinx) and this script
turns that HTML into README.md.

antsibull has no Markdown output and Sphinx has no Markdown builder that
understands antsibull's option tables, so we convert the finished HTML instead:

  - The prose sections (Synopsis, Notes, Examples, Authors) are a straight
    pandoc HTML -> GitHub-Flavored-Markdown conversion.
  - The Parameters and Attributes tables are rebuilt as real Markdown pipe
    tables (not embedded HTML). Galaxy sanitizes the Markdown it renders
    (markdown + nh3) and strips the CSS classes antsibull uses for indentation,
    which would flatten nested options, so we encode the nesting ourselves: an
    option's anchor path (parent/child/grandchild) gives its depth, shown with
    one bullet marker per level in the Parameter column. Cell content is kept on
    a single line (type, description, choices and default folded inline) because
    a Markdown pipe-table cell cannot contain a line break without an HTML <br>.
    The columns are padded with spaces (format_pipe_table) so the table reads
    like a real table as plain text; the padding is stripped when rendered.

Because this parses antsibull's rendered HTML (anchor id paths for depth, the
ansible-option-type-line for the type, the choices <li> list, the Default:
marker), the table parsing here needs updating if antsibull changes that HTML.
Where an expected marker is missing the script exits with a message naming it,
rather than failing with an opaque traceback.

Usage: .html_to_md.py SPHINX_HTML_PAGE OUTPUT_README_MD
"""

import html
import re
import subprocess
import sys

# The bullet marker prepended once per nesting level in the Parameter column.
NEST_MARKER = "\N{BULLET} "


# --- pandoc helpers --------------------------------------------------------


def run_pandoc(fragment):
    """Convert an HTML fragment to GitHub-Flavored Markdown (raw, multi-line)."""
    return subprocess.run(
        ["pandoc", "-f", "html", "-t", "gfm", "--wrap=none"],
        input=fragment,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def collapse(text):
    """Squeeze all runs of whitespace (incl. newlines) into single spaces."""
    return " ".join(text.split())


def pandoc_inline_many(fragments):
    """Convert many HTML fragments in one pandoc call, one output line each.

    Pipe-table cells must be a single source line, so each result is collapsed
    onto one line. The fragments are joined with a unique marker paragraph and
    converted together (one subprocess instead of one per cell), then the output
    is split back apart on that marker. Each fragment renders as its own
    paragraph, so combining them does not change any individual result.

    Returns a list of Markdown strings, one per input fragment (same order).
    """
    if not fragments:
        return []
    marker = "@@CELLBREAK@@"
    joined = f"\n\n<p>{marker}</p>\n\n".join(frag or "<p></p>" for frag in fragments)
    pieces = run_pandoc(joined).split(marker)
    return [collapse(piece) for piece in pieces]


# --- small HTML utilities --------------------------------------------------


def strip_tags(text):
    return re.sub(r"<[^>]+>", "", text)


def unwrap_spans(text):
    """Remove <span> wrappers, keeping their text (innermost first).

    Sphinx nests spans (e.g. inline literals split one <span class="pre"> per
    word, cross-references add std-ref spans); flattening them lets pandoc and
    the table parser see clean text instead of per-word fragments.
    """
    while True:
        unwrapped = re.sub(r"<span[^>]*>([^<]*)</span>", r"\1", text)
        if unwrapped == text:
            return text
        text = unwrapped


def esc_cell(text):
    """Escape the pipe character so cell content cannot break the table."""
    return text.replace("|", "\\|")


def code_text(fragment):
    """Return the unescaped text inside the first <code> tag, else ''."""
    code = re.search(r"<code[^>]*>(.*?)</code>", fragment, re.S)
    return html.unescape(strip_tags(code.group(1))).strip() if code else ""


# --- pipe-table rendering --------------------------------------------------


def format_pipe_table(headers, rows):
    """Render a Markdown pipe table with space-aligned columns.

    Cells are padded so the column borders line up in the raw Markdown, which
    makes README.md read like a real table in a plain-text editor. The extra
    spaces are valid GFM and are stripped when Galaxy/GitHub render the table, so
    the rendered output is unchanged. The final column is left ragged: its cells
    (descriptions) are long single lines, so padding them to the widest cell
    would only add a wall of trailing spaces to every row.

    headers is the list of column names; rows is a list of already-escaped cell
    lists, one per column.
    """
    last = len(headers) - 1
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def line(cells):
        padded = [
            cell if index == last else cell.ljust(widths[index])
            for index, cell in enumerate(cells)
        ]
        return "| " + " | ".join(padded) + " |"

    separator = [
        "---" if index == last else "-" * widths[index]
        for index in range(len(headers))
    ]
    return "\n".join([line(headers), line(separator), *(line(row) for row in rows)])


def cell_rows(table_html):
    """Yield the list of <td> inner-HTML strings for each non-header row."""
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", table_html, re.S):
        if "<th" in row:
            continue
        yield re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)


def cell_inner(cell_td):
    """Return the content inside the <div class="ansible-option-cell"> wrapper."""
    inner = re.search(r'<div class="ansible-option-cell">(.*)</div>', cell_td, re.S)
    return inner.group(1) if inner else cell_td


def require(match, what):
    """Return match.group(1), or exit if the expected HTML marker is missing."""
    if not match:
        sys.exit(
            f"error: {what} not found in the role HTML; antsibull's markup "
            "likely changed (see this script's module docstring)"
        )
    return match.group(1)


def param_label(param_td):
    """Build the Parameter-column label: bullet-nesting + **name** *type*."""
    path = require(
        re.search(r'id="parameter-main--([^"]*)"', param_td),
        'an option anchor id ("parameter-main--...")',
    )
    name = path.split("/")[-1]
    type_line = re.search(
        r'<p class="ansible-option-type-line">(.*?)</p>', param_td, re.S
    )
    type_text = " ".join(strip_tags(type_line.group(1)).split()) if type_line else ""
    label = f"**{name}**"
    if type_text:
        label += f" *{type_text}*"  # type inline after the name, italic
    return NEST_MARKER * path.count("/") + label  # one marker per nesting level


def comment_description_html(cell):
    """Return the HTML of the option's description (before any Choices/Default)."""
    split_at = len(cell)
    for marker in (r'<p class="ansible-option-line">', r'<ul class="simple">'):
        found = re.search(marker, cell)
        if found:
            split_at = min(split_at, found.start())
    return cell[:split_at].strip()


def comment_suffix(cell):
    """Return the inline "Choices:"/"Default:" text for an option cell (no pandoc)."""
    choices = re.search(r'<ul class="simple">(.*?)</ul>', cell, re.S)
    if choices:
        values = []
        for item in re.findall(r"<li>(.*?)</li>", choices.group(1), re.S):
            value = code_text(item)
            default = " (default)" if "ansible-option-default-bold" in item else ""
            values.append(f"`{value}`{default}")
        return "**Choices:** " + ", ".join(values)
    # Options without choices may carry a standalone Default: line.
    default = re.search(r"Default:</strong>.*?<code[^>]*>(.*?)</code>", cell, re.S)
    if default:
        value = html.unescape(strip_tags(default.group(1))).strip()
        if value:
            return f"**Default:** `{value}`"
    return ""


def build_parameters(table_html):
    """Rebuild the Parameters table as a space-aligned pipe table with nesting."""
    labels, cells = [], []
    for tds in cell_rows(table_html):
        labels.append(param_label(tds[0]))
        cells.append(cell_inner(tds[1]))
    descriptions = pandoc_inline_many([comment_description_html(c) for c in cells])
    rows = []
    for label, cell, description in zip(labels, cells, descriptions):
        comment = " ".join(part for part in (description, comment_suffix(cell)) if part)
        rows.append([esc_cell(label), esc_cell(comment)])
    return format_pipe_table(["Parameter", "Comments"], rows)


def build_attributes(table_html):
    """Rebuild the Attributes table (Attribute / Support / Description)."""
    names, supports_html, descriptions_html = [], [], []
    for tds in cell_rows(table_html):
        names.append(require(
            re.search(r'id="attribute-([^"]*)"', tds[0]),
            'an attribute anchor id ("attribute-...")',
        ))
        # Drop the redundant "Support:" label (the column header already says it).
        supports_html.append(re.sub(
            r'<strong class="ansible-attribute-support-label">.*?</strong>',
            "",
            cell_inner(tds[1]),
            flags=re.S,
        ))
        descriptions_html.append(cell_inner(tds[2]))
    supports = pandoc_inline_many(supports_html)
    descriptions = pandoc_inline_many(descriptions_html)
    rows = [
        [esc_cell(f"**{name}**"), esc_cell(support), esc_cell(description)]
        for name, support, description in zip(names, supports, descriptions)
    ]
    return format_pipe_table(["Attribute", "Support", "Description"], rows)


# --- page body extraction and cleanup --------------------------------------


def extract_body(doc):
    """Return the <div role="main"> block, tag-matching its nested <div>s."""
    start = doc.find('<div role="main"')
    if start < 0:
        sys.exit('error: could not find <div role="main"> in the HTML page')
    depth = 0
    for match in re.finditer(r"<(/?)div\b", doc[start:]):
        depth += -1 if match.group(1) else 1
        if depth == 0:
            return doc[start : doc.find("</div>", start + match.start()) + 6]
    sys.exit('error: unbalanced <div> in the HTML page body')


def gh_slug(text):
    """Return the heading anchor GitHub derives from a heading's text."""
    slug = text.strip().lower()
    slug = re.sub(r"[^\w\- ]", "", slug)  # drop the punctuation GitHub removes
    return slug.replace(" ", "-")


def link_toc(body):
    """Point the local contents TOC at GitHub-style in-file section anchors.

    Sphinx's own anchor ids differ from the ones GitHub derives from the
    rendered headings, so recompute each TOC link target from its text. Dropping
    the "reference internal" class also keeps these links (unlike the in-option
    cross-references) from being flattened to plain text later.
    """
    nav = re.search(r'<nav class="contents local"[^>]*>.*?</nav>', body, re.S)
    if not nav:
        return body

    def fix(match):
        inner = match.group(1)
        text = html.unescape(strip_tags(inner)).strip()
        return f'<a href="#{gh_slug(text)}">{inner}</a>'

    fixed = re.sub(
        r'<a class="reference internal"[^>]*>(.*?)</a>', fix, nav.group(0), flags=re.S
    )
    return body[: nav.start()] + fixed + body[nav.end() :]


def strip_sphinx_chrome(body):
    """Remove Sphinx/antsibull HTML scaffolding that does not belong in Markdown."""
    # Flatten spans so both the table parser and pandoc see clean text.
    body = unwrap_spans(body)
    # Turn the contents TOC into working in-file section links, then flatten the
    # remaining in-page cross-references (they point at anchors a flat README
    # lacks) to plain text.
    body = link_toc(body)
    body = re.sub(
        r'<a[^>]*class="reference internal"[^>]*>(.*?)</a>', r"\1", body, flags=re.S
    )
    # Drop the "Note" title Sphinx puts on admonition boxes; the box is gone in
    # Markdown, so the bare label is just noise.
    body = re.sub(r'<p class="admonition-title">.*?</p>', "", body, flags=re.S)
    # Drop Sphinx heading permalink icons and unwrap the toc-backref anchors that
    # wrap each heading; otherwise pandoc emits the heading as raw HTML and leaves
    # its inline code as literal <code> tags instead of Markdown backticks.
    body = re.sub(r'<a[^>]*class="headerlink"[^>]*>.*?</a>', "", body, flags=re.S)
    body = re.sub(
        r'<a[^>]*class="toc-backref"[^>]*>(.*?)</a>', r"\1", body, flags=re.S
    )
    # Drop the class from the remaining (external) links; pandoc cannot represent
    # it in a Markdown link and would otherwise keep the whole anchor as raw HTML.
    body = re.sub(r'(<a\b[^>]*?)\s+class="[^"]*"', r"\1", body)
    return body


def build_code_blocks(body):
    """Swap Sphinx highlight blocks for placeholders; return (body, blocks).

    pandoc would render them as indented code blocks, so instead we emit fenced
    ```yaml blocks (the Examples use YAML) and splice them back after pandoc.
    """
    blocks = {}

    def replace(match):
        pre = re.search(r"<pre>(.*?)</pre>", match.group(0), re.S).group(1)
        code = html.unescape(strip_tags(pre)).strip("\n")
        key = f"@@CODE{len(blocks)}@@"
        blocks[key] = f"```yaml\n{code}\n```"
        return f"<p>{key}</p>"

    body = re.sub(
        r'<div class="highlight-[^"]*"[^>]*>.*?</pre>\s*</div>\s*</div>',
        replace,
        body,
        flags=re.S,
    )
    return body, blocks


def replace_option_tables(body, replacements):
    """Swap each antsibull option table for a placeholder; build the pipe table.

    The built tables are stored in `replacements` (keyed by placeholder) and
    spliced back after pandoc so pandoc never sees — and never mangles — an HTML
    table. Parameters and Attributes tables are told apart by their anchor ids.
    """
    tables = re.findall(
        r"<table[^>]*ansible-option-table[^>]*>.*?</table>", body, re.S
    )
    for index, table in enumerate(tables):
        key = f"@@TABLE{index}@@"
        if "parameter-main--" in table:
            replacements[key] = build_parameters(table)
        else:
            replacements[key] = build_attributes(table)
        body = body.replace(table, f"<p>{key}</p>", 1)
    return body


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} SPHINX_HTML_PAGE OUTPUT_README_MD")
    html_path, md_path = sys.argv[1], sys.argv[2]

    with open(html_path, encoding="utf-8") as handle:
        body = extract_body(handle.read())

    body = strip_sphinx_chrome(body)
    # Swap the code blocks and option tables for placeholders so pandoc never
    # sees them; both are spliced back from `replacements` after conversion.
    body, replacements = build_code_blocks(body)
    body = replace_option_tables(body, replacements)

    md = run_pandoc(body)

    # Clean up Sphinx-isms pandoc passes through.
    md = re.sub(r"</?div[^>]*>\n?", "", md)  # section wrapper divs
    md = re.sub(r"\n{3,}", "\n\n", md)

    for key, rendered in replacements.items():
        md = md.replace(key, rendered)

    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(md.rstrip("\n") + "\n")  # exactly one trailing newline


if __name__ == "__main__":
    main()
