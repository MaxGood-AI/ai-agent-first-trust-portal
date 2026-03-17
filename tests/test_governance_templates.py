"""Tests for governance document templates."""

import os

import pytest

TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "templates", "governance"
)

REQUIRED_SECTIONS = [
    "## Platform Overview",
    "## Repository Map",
    "## Cross-Cutting Conventions",
    "## KanbanZone Card Workflow",
    "## KanbanZone Agent Access",
    "## Linting",
    "## Testing",
    "## Definition of Done",
    "## Discrepancy Rule",
    "## Key Domain Terms",
    "## SOC 2 Evidence Chain",
    '## The "done." Protocol',
    "## Commit Style",
    "## Decision Log Capture",
]


def _read_template(filename):
    path = os.path.join(TEMPLATES_DIR, filename)
    with open(path) as f:
        return f.read()


def test_templates_directory_exists():
    assert os.path.isdir(TEMPLATES_DIR)


def test_claude_template_exists():
    assert os.path.isfile(os.path.join(TEMPLATES_DIR, "CLAUDE.md.template"))


def test_agents_template_exists():
    assert os.path.isfile(os.path.join(TEMPLATES_DIR, "AGENTS.md.template"))


def test_setup_guide_exists():
    assert os.path.isfile(os.path.join(TEMPLATES_DIR, "GOVERNANCE-SETUP.md"))


@pytest.mark.parametrize("section", REQUIRED_SECTIONS)
def test_claude_template_has_required_section(section):
    content = _read_template("CLAUDE.md.template")
    assert section in content, f"CLAUDE.md.template missing section: {section}"


@pytest.mark.parametrize("section", REQUIRED_SECTIONS)
def test_agents_template_has_required_section(section):
    content = _read_template("AGENTS.md.template")
    assert section in content, f"AGENTS.md.template missing section: {section}"


def test_agents_template_has_review_protocol():
    content = _read_template("AGENTS.md.template")
    assert "### Independent Code Review Protocol" in content


def test_claude_template_does_not_have_review_protocol():
    content = _read_template("CLAUDE.md.template")
    assert "### Independent Code Review Protocol" not in content


def test_templates_have_placeholders():
    for filename in ["CLAUDE.md.template", "AGENTS.md.template"]:
        content = _read_template(filename)
        assert "{{ LEGAL_ENTITY }}" in content
        assert "{{ PLATFORM_DESCRIPTION }}" in content
        assert "{{ DOMAIN_TERMS }}" in content
        assert "<!-- CUSTOMIZE" in content


def test_templates_no_maxgood_references():
    for filename in ["CLAUDE.md.template", "AGENTS.md.template"]:
        content = _read_template(filename)
        assert "MaxGood" not in content, f"{filename} contains MaxGood-specific reference"
        assert "maxgood" not in content, f"{filename} contains MaxGood-specific reference"


def test_setup_guide_has_all_steps():
    content = _read_template("GOVERNANCE-SETUP.md")
    assert "## Step 1" in content
    assert "## Step 2" in content
    assert "## Step 3" in content
    assert "## Step 4" in content
    assert "## Step 5" in content
    assert "## Step 6" in content
    assert "## Step 7" in content


def test_review_prompt_exists():
    assert os.path.isfile(os.path.join(TEMPLATES_DIR, "REVIEW-PROMPT.md"))


def test_review_prompt_has_placeholders():
    content = _read_template("REVIEW-PROMPT.md")
    assert "{{ CARD_NUMBER }}" in content
    assert "{{ BOARD_URL }}" in content
    assert "{{ REPO_LIST }}" in content


def test_review_prompt_has_verdict():
    content = _read_template("REVIEW-PROMPT.md")
    assert "VERDICT: PASS" in content
    assert "VERDICT: FAIL" in content


def test_review_prompt_covers_all_checks():
    content = _read_template("REVIEW-PROMPT.md")
    assert "Security" in content
    assert "Unit tests" in content
    assert "E2E tests" in content
    assert "edge cases" in content
    assert "malicious" in content
    assert "Lint" in content


def test_workflow_references_review_prompt():
    for filename in ["CLAUDE.md.template", "AGENTS.md.template"]:
        content = _read_template(filename)
        assert "REVIEW-PROMPT.md" in content, f"{filename} workflow doesn't reference REVIEW-PROMPT.md"
        assert "independent code review" in content.lower(), f"{filename} workflow missing review step"
