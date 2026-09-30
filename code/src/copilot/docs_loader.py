"""Load capped in-app Docs markdown from ``web/content/docs`` TypeScript sources."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# code/src/copilot → repo root (fft/)
_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DOCS_ROOT = _REPO_ROOT / "web" / "content" / "docs"
DEFAULT_DOCS_TREE = _REPO_ROOT / "web" / "lib" / "docs-tree.ts"

_SLUG_SAFE = re.compile(r"^[a-z0-9][a-z0-9_/-]*$", re.IGNORECASE)
_FIELD_RE = re.compile(
    r'slug:\s*"(?P<slug>[^"]+)"\s*,\s*'
    r'title:\s*"(?P<title>[^"]+)"\s*,\s*'
    r'part:\s*"(?P<part>[^"]+)"\s*,\s*'
    r"contentPhase:\s*(?P<phase>\d+)\s*,\s*"
    r'summary:\s*"(?P<summary>[^"]*)"',
    re.MULTILINE,
)

# Keyword / phrase → preferred Docs slugs (rule-based RAG routing).
_DOC_QUERY_ROUTES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        (
            "explain the project",
            "what is this project",
            "what is the project",
            "about the project",
            "about this project",
            "what is this product",
            "what is this system",
            "what is this lab",
            "what does this do",
            "overview",
            "about this",
        ),
        ("getting-started", "getting-started/what-this-is"),
    ),
    (
        ("project", "product", "system", "lab", "platform"),
        ("getting-started/what-this-is", "getting-started"),
    ),
    (
        ("quick start", "get started", "first run", "how do i start", "getting started"),
        ("getting-started/quick-start", "getting-started"),
    ),
    (
        ("concept", "glossary", "what is an incident", "what is an analysis"),
        ("getting-started/concepts",),
    ),
    (
        ("copilot", "ai insight", "add to chat"),
        ("getting-started/copilot",),
    ),
    (
        ("non-goal", "does not do", "not a siem", "limitation", "shortcoming"),
        ("getting-started/non-goals",),
    ),
    (
        ("audience", "who is it for", "who it is for"),
        ("getting-started/audience",),
    ),
    (
        ("why flagged", "playbook"),
        ("workflows/why-flagged", "reference/playbooks"),
    ),
    (
        ("triage",),
        ("workflows/triage", "navigate/triage"),
    ),
    (
        ("pipeline", "stage order", "stages"),
        ("pipeline/stages", "getting-started"),
    ),
    (
        ("upload", "land logs"),
        ("workflows/upload", "getting-started/quick-start"),
    ),
    (
        ("report",),
        ("workflows/reports", "navigate/reports"),
    ),
    (
        ("robust z", "threshold", "detector maths", "welch", "cusum"),
        ("maths/overview", "maths/robust-z"),
    ),
    (
        ("setup", "install", "env", ".env", "configuration"),
        ("reference/setup", "pipeline/config"),
    ),
    (
        ("security", "auth", "sso", "login"),
        ("reference/security", "getting-started/non-goals"),
    ),
    (
        ("troubleshoot", "error", "broken"),
        ("reference/troubleshooting",),
    ),
)


class DocsLoadError(Exception):
    """Docs slug missing or unsafe."""


def default_docs_root() -> Path:
    return DEFAULT_DOCS_ROOT


def default_docs_tree_path() -> Path:
    return DEFAULT_DOCS_TREE


def is_safe_docs_slug(slug: str) -> bool:
    text = (slug or "").strip().strip("/")
    if not text or ".." in text or text.startswith("/") or "\\" in text:
        return False
    return _SLUG_SAFE.fullmatch(text) is not None

def _parse_js_string_array(body: str) -> list[str]:
    """Parse a JS array of double-quoted strings (Docs part files)."""
    strings: list[str] = []
    index = 0
    length = len(body)
    while index < length:
        while index < length and body[index] in " \t\r\n,":
            index += 1
        if index >= length:
            break
        if body[index] != '"':
            # Skip non-string tokens (should not appear in our Docs arrays).
            index += 1
            continue
        index += 1
        chunk: list[str] = []
        while index < length:
            char = body[index]
            if char == "\\":
                if index + 1 < length:
                    nxt = body[index + 1]
                    escapes = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
                    chunk.append(escapes.get(nxt, nxt))
                    index += 2
                    continue
            if char == '"':
                index += 1
                break
            chunk.append(char)
            index += 1
        strings.append("".join(chunk))
    return strings


def _markdown_for_slug(source: str, slug: str) -> str | None:
    marker = f'"{slug}":'
    start = 0
    while True:
        idx = source.find(marker, start)
        if idx < 0:
            return None
        # Ensure key boundary (not a longer string containing the slug).
        if idx > 0 and source[idx - 1] not in " \t\n\r,{":
            start = idx + len(marker)
            continue
        window = source[idx : idx + 12_000]
        md_key = window.find("markdown:")
        if md_key < 0:
            start = idx + len(marker)
            continue
        bracket = window.find("[", md_key)
        if bracket < 0:
            start = idx + len(marker)
            continue
        depth = 0
        end = None
        for pos in range(bracket, len(window)):
            char = window[pos]
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end is None:
            start = idx + len(marker)
            continue
        lines = _parse_js_string_array(window[bracket + 1 : end])
        return "\n".join(lines)
    return None


def load_docs_markdown(
    slug: str,
    *,
    docs_root: Path | None = None,
    max_chars: int = 6000,
) -> dict[str, object]:
    """Return ``{slug, markdown, truncated}`` for an allow-listed Docs slug."""
    if not is_safe_docs_slug(slug):
        raise DocsLoadError(f"invalid docs slug: {slug!r}")
    normalized = slug.strip().strip("/")
    root = docs_root if docs_root is not None else default_docs_root()
    if not root.is_dir():
        raise DocsLoadError(f"docs root not found: {root}")

    for path in sorted(root.glob("*.ts")):
        text = path.read_text(encoding="utf-8")
        markdown = _markdown_for_slug(text, normalized)
        if markdown is None:
            continue
        truncated = len(markdown) > max_chars
        return {
            "slug": normalized,
            "markdown": markdown[:max_chars],
            "truncated": truncated,
            "source_file": path.name,
        }
    raise DocsLoadError(f"docs slug not found: {normalized}")


def load_docs_catalog(*, tree_path: Path | None = None) -> list[dict[str, str]]:
    """Parse ``docs-tree.ts`` into ``{slug, title, summary, part}`` rows."""
    path = tree_path if tree_path is not None else default_docs_tree_path()
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _FIELD_RE.finditer(text):
        slug = match.group("slug").strip().strip("/")
        if not is_safe_docs_slug(slug) or slug in seen:
            continue
        seen.add(slug)
        rows.append(
            {
                "slug": slug,
                "title": match.group("title"),
                "summary": match.group("summary"),
                "part": match.group("part"),
            }
        )
    return rows


@lru_cache(maxsize=1)
def _cached_docs_catalog() -> tuple[tuple[str, str, str, str], ...]:
    rows = load_docs_catalog()
    return tuple(
        (row["slug"], row["title"], row["summary"], row["part"]) for row in rows
    )


def _score_catalog_entry(query: str, title: str, summary: str, slug: str) -> int:
    hay = f"{title} {summary} {slug.replace('/', ' ')}".lower()
    score = 0
    for token in re.findall(r"[a-z0-9]+", query.lower()):
        if len(token) < 3:
            continue
        if token in hay:
            score += 2 if token in title.lower() or token in slug.lower() else 1
    return score


def resolve_docs_slugs_for_query(
    query: str,
    *,
    max_slugs: int = 2,
    tree_path: Path | None = None,
) -> list[str]:
    """Pick allow-listed Docs slugs for a natural-language question.

    Preference order: phrase routes → catalog keyword overlap → Getting started hub.
    """
    text = (query or "").strip().lower()
    if not text:
        return []

    cap = max(1, int(max_slugs))
    chosen: list[str] = []

    def _push(slug: str) -> None:
        if not is_safe_docs_slug(slug):
            return
        normalized = slug.strip().strip("/")
        if normalized not in chosen:
            chosen.append(normalized)

    for phrases, slugs in _DOC_QUERY_ROUTES:
        if any(phrase in text for phrase in phrases):
            for slug in slugs:
                _push(slug)
                if len(chosen) >= cap:
                    return chosen[:cap]

    catalog = (
        load_docs_catalog(tree_path=tree_path)
        if tree_path is not None
        else [
            {
                "slug": slug,
                "title": title,
                "summary": summary,
                "part": part,
            }
            for slug, title, summary, part in _cached_docs_catalog()
        ]
    )
    scored: list[tuple[int, str]] = []
    for row in catalog:
        score = _score_catalog_entry(
            text, row["title"], row["summary"], row["slug"]
        )
        if score > 0:
            scored.append((score, row["slug"]))
    scored.sort(key=lambda item: (-item[0], item[1]))
    for _score, slug in scored:
        _push(slug)
        if len(chosen) >= cap:
            return chosen[:cap]

    # Product / how-to questions with no incident still need Docs grounding.
    general = any(
        token in text
        for token in (
            "explain",
            "what",
            "how",
            "project",
            "product",
            "system",
            "lab",
            "work",
            "help",
            "docs",
            "documentation",
        )
    )
    if general and not chosen:
        _push("getting-started")
        _push("getting-started/what-this-is")

    return chosen[:cap]
