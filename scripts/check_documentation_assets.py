"""Zero-network validation of README and docs links, assets and screenshots.

Checks that every relative link and image path in the repository's Markdown
resolves, that every referenced SVG parses and declares accessible metadata,
that the screenshot manifest matches the files on disk, and that no
documentation asset leaks a credential-shaped value.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_ROOTS = (REPO_ROOT / "README.md", REPO_ROOT / "AGENTS.md", REPO_ROOT / "docs")
SCREENSHOT_MANIFEST = REPO_ROOT / "docs/assets/screenshots/manifest.json"
MAX_SCREENSHOT_BYTES = 1_048_576

_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)\)")
_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)|<img[^>]*\ssrc=\"([^\"]+)\"")
_ANCHOR_TEXT = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)
#: Shapes that must never appear in documentation.
_FORBIDDEN = (
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"sb_secret_[A-Za-z0-9]{8,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{20,}"),
    re.compile(r"X-Amz-Signature", re.IGNORECASE),
    re.compile(r"Authorization:\s*Bearer\s+(?!<)", re.IGNORECASE),
)


def _slug(heading: str) -> str:
    """Mirror GitHub's anchor slug: strip punctuation, then map each space to a hyphen.

    GitHub does not collapse whitespace runs, so "A — B" becomes "a--b" once the
    em dash is removed. Collapsing here would reject valid links.
    """
    text = re.sub(r"<[^>]+>", "", heading).strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return text.replace(" ", "-")


def _markdown_files() -> list[Path]:
    files: list[Path] = []
    for root in MARKDOWN_ROOTS:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(sorted(root.rglob("*.md")))
    return files


def _check_targets(path: Path, failures: list[str]) -> None:
    text = path.read_text("utf-8")
    anchors = {_slug(heading) for heading in _ANCHOR_TEXT.findall(text)}
    targets = [match for match in _LINK.findall(text)]
    targets += [image or html for image, html in _IMAGE.findall(text)]
    for target in targets:
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        if target.startswith("#"):
            if _slug(target[1:]) not in anchors:
                failures.append(f"{path.relative_to(REPO_ROOT)}: missing anchor {target}")
            continue
        resolved = (path.parent / urlsplit(target).path).resolve()
        if not resolved.exists():
            failures.append(f"{path.relative_to(REPO_ROOT)}: missing path {target}")


def _check_svgs(failures: list[str]) -> int:
    svgs = sorted((REPO_ROOT / "docs/assets").rglob("*.svg"))
    for svg in svgs:
        try:
            root = ElementTree.fromstring(svg.read_text("utf-8"))
        except ElementTree.ParseError as exc:
            failures.append(f"{svg.relative_to(REPO_ROOT)}: invalid SVG ({exc.msg})")
            continue
        namespace = "{http://www.w3.org/2000/svg}"
        if root.find(f"{namespace}title") is None or root.find(f"{namespace}desc") is None:
            failures.append(f"{svg.relative_to(REPO_ROOT)}: missing <title> or <desc>")
        body = svg.read_text("utf-8")
        for token in ("<script", "xlink:href=\"http", "href=\"http"):
            if token in body:
                failures.append(f"{svg.relative_to(REPO_ROOT)}: forbidden remote or script content")
        if svg.stat().st_size > 300_000:
            failures.append(f"{svg.relative_to(REPO_ROOT)}: larger than 300 KB")
    return len(svgs)


def _check_screenshots(failures: list[str]) -> int:
    if not SCREENSHOT_MANIFEST.is_file():
        failures.append("docs/assets/screenshots/manifest.json is missing")
        return 0
    manifest = json.loads(SCREENSHOT_MANIFEST.read_text("utf-8"))
    entries = manifest.get("screenshots", [])
    forbidden_fields = {"cookies", "headers", "token", "authorization", "query"}
    for entry in entries:
        if forbidden_fields & set(entry):
            failures.append("screenshot manifest carries a forbidden field")
        image = SCREENSHOT_MANIFEST.parent / entry["filename"]
        if not image.is_file():
            failures.append(f"screenshot {entry['filename']} is missing")
            continue
        payload = image.read_bytes()
        if hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            failures.append(f"screenshot {entry['filename']} does not match its recorded digest")
        if len(payload) != entry["byte_size"]:
            failures.append(f"screenshot {entry['filename']} byte size drifted")
        if len(payload) > MAX_SCREENSHOT_BYTES:
            failures.append(f"screenshot {entry['filename']} exceeds 1 MiB")
        if entry["http_status"] >= 400:
            failures.append(f"screenshot {entry['filename']} captured an error page")
        if "?" in entry["route"]:
            failures.append(f"screenshot {entry['filename']} route carries a query string")
    return len(entries)


def _check_secrets(files: list[Path], failures: list[str]) -> None:
    for path in files:
        text = path.read_text("utf-8")
        for pattern in _FORBIDDEN:
            if pattern.search(text):
                failures.append(f"{path.relative_to(REPO_ROOT)}: forbidden credential-shaped value")


def main() -> int:
    failures: list[str] = []
    files = _markdown_files()
    for path in files:
        _check_targets(path, failures)
    _check_secrets(files, failures)
    svg_count = _check_svgs(failures)
    shot_count = _check_screenshots(failures)

    print(f"markdown files: {len(files)}")
    print(f"svg assets:     {svg_count}")
    print(f"screenshots:    {shot_count}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("PASS: documentation links, assets and screenshots are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
