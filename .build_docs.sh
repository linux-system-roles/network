#!/usr/bin/env bash
# Build the README files for this role from meta/argument_specs.yml.
#
# antsibull-docs turns argument_specs.yml into RST, Sphinx renders that RST to
# HTML (the same way the official Ansible website builds its docs), and pandoc
# converts the HTML to Markdown. Requires antsibull-docs, sphinx and pandoc on
# PATH.
#
# The script creates these at the repo root:
#   README.md    - the role's main README. People read it directly as plain
#                  text in the repo, and Markdown viewers render it: GitHub,
#                  Ansible Galaxy and Red Hat Automation Hub (the last two
#                  display role docs only as Markdown). This is the canonical
#                  README; it supersedes the plain-text and RST renderings,
#                  which are intentionally not emitted.
#   README.html  - link to the full styled page in sphinx_html/
#   sphinx_html/ - the Sphinx HTML output (the page plus its _static assets)
#
# RST is still produced internally (antsibull emits it and Sphinx consumes it to
# build the HTML) but is not copied out as README.rst.
#
# Markdown is produced from the Sphinx HTML by the .html_to_md.py helper (which
# calls pandoc). antsibull has no Markdown output and Sphinx has no Markdown
# builder that understands antsibull's option tables, so we convert the finished
# HTML instead. The Parameters and Attributes tables become real Markdown pipe
# tables (Galaxy strips the CSS classes antsibull uses to indent nested options,
# so .html_to_md.py encodes the nesting as dot markers in the Parameter column).
#
# NOTE: the HTML output (README.html + sphinx_html/) is included here only
# to preview the styled page in the draft PR. The bundled fonts are trimmed to
# just the FontAwesome icon font (see below), so it is ~0.6MB rather than ~10MB;
# body text falls back to the system sans-serif. Long term, the
# full styled site is built once for the whole fedora.linux_system_roles
# collection, not per role, to keep each role repo small. README.html is a
# link, so commit the sphinx_html folder with it or the link will not resolve.
#
# antsibull-docs works with collections only. This repo has one role and
# is not a collection, so we first copy the role into a temporary
# fedora.linux_system_roles collection. Inside the real collection you do
# not need this step.
#
# Usage: ./.build_docs.sh

set -euo pipefail

for tool in antsibull-docs sphinx-build pandoc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool not found on PATH" >&2; exit 1; }
done

ROLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROLE_NAME="$(basename "$ROLE_DIR")"
OUT_DIR="$ROLE_DIR/sphinx_html"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Copy this single role into a temporary collection.
COLL="$WORK/collections/ansible_collections/fedora/linux_system_roles"
mkdir -p "$COLL/roles"
ln -s "$ROLE_DIR" "$COLL/roles/$ROLE_NAME"
# version is mandatory but only used for the "part of the collection" note;
# leave it empty so antsibull omits the version from that note (this per-role
# build has no meaningful collection version).
cat > "$COLL/galaxy.yml" <<EOF
namespace: fedora
name: linux_system_roles
version: ""
readme: README.md
authors: [Linux System Roles]
EOF
echo "# linux_system_roles" > "$COLL/README.md"
export ANSIBLE_COLLECTIONS_PATH="$WORK/collections"

# antsibull makes the config files it needs: conf.py, antsibull-docs.cfg.
mkdir -p "$WORK/site"
antsibull-docs sphinx-init --use-current --squash-hierarchy \
    --dest-dir "$WORK/site" fedora.linux_system_roles

cd "$WORK/site"

# 1. antsibull turns argument_specs.yml into RST (same command as its build.sh).
# The RST is a build intermediate (Sphinx input below); it is not copied out.
chmod og-w rst   # antsibull-docs wants this directory writable only by its owner
antsibull-docs --config-file antsibull-docs.cfg collection \
    --cleanup everything --use-current --squash-hierarchy \
    --dest-dir rst fedora.linux_system_roles

# Ship only the rendered page, not its RST source. By default Sphinx copies
# the .rst files into _sources/ and adds a "Show Source" link; turn both off.
printf '\nhtml_copy_source = False\nhtml_show_sourcelink = False\n' >> conf.py

# 2. Sphinx renders the RST to the styled HTML site (for the draft PR preview).
sphinx-build -M html rst build -q -c .

# antsibull always renders a role by its collection FQCN (namespace.name.role).
# This role group is also published as classic Galaxy roles, so rewrite the
# role's FQCN "fedora.linux_system_roles.<role>" to the legacy role name
# "linux-system-roles.<role>" in the generated HTML, before it is copied out and
# converted to Markdown, so both the HTML preview and the derived README.md pick
# it up. Only the full role name is rewritten; bare "fedora.linux_system_roles"
# collection references (the "part of the collection" / "collection install"
# note) and the galaxy.ansible.com URL (which uses slashes) are left untouched.
find build/html -type f \( -name '*.html' -o -name 'searchindex.js' \) -print0 \
    | xargs -0 sed -i "s/fedora\.linux_system_roles\.${ROLE_NAME}/linux-system-roles.${ROLE_NAME}/g"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -r build/html/. "$OUT_DIR"             # styled page plus its _static assets
rm -rf "$OUT_DIR/_sources"                # empty leftover dir (RST source is not shipped)
# Trim the bundled fonts to just the FontAwesome icon font (woff2). The
# sphinx_rtd_theme ships Lato and Roboto Slab (body/heading text) plus
# FontAwesome (the UI icons: menu, home, previous/next) in four formats
# (ttf/woff/woff2/eot, ~9MB). The icon font is only ~75KB and has no system
# fallback, so keep it; the text fonts are ~1.8MB and fall back cleanly to the
# system sans-serif, so drop them. This cuts sphinx_html from ~10MB to ~0.6MB
# while keeping every UI icon. Scope the delete to the font directories so it
# cannot touch the SVG logos under _static/images.
for fontdir in "$OUT_DIR/_static/fonts" "$OUT_DIR/_static/css/fonts"; do
    [ -d "$fontdir" ] && find "$fontdir" -type f ! -iname 'fontawesome-webfont.woff2' -delete
done
ln -sfn "sphinx_html/${ROLE_NAME}_role.html" "$ROLE_DIR/README.html"

# 3. .html_to_md.py turns the HTML page into the main README.md (it calls pandoc
# for the prose and rebuilds the option tables as pipe tables).
python3 "$ROLE_DIR/.html_to_md.py" \
    "build/html/${ROLE_NAME}_role.html" "$ROLE_DIR/README.md"

echo "MD  : $ROLE_DIR/README.md"
echo "HTML: $ROLE_DIR/README.html -> sphinx_html/${ROLE_NAME}_role.html"
