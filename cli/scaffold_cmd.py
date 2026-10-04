"""``python -m cli scaffold`` — create the two repositories a new organisation
connects to the portal.

  python -m cli scaffold --governance-dir DIR --evidence-dir DIR --company "Legal Name" [--force]

Governance repository (a git source with role ``governance``):
  policies/*.md           the policy templates of this portal (to be customised)
  CLAUDE.md, AGENTS.md    agent governance documents (from templates/governance)
  README.md               what the repository is and how the portal reads it
  infrastructure/README.md, agent-config/README.md

Evidence repository (a git source with role ``evidence``), laid out per
``docs/evidence-repo-spec.md``:
  .evidence-repo.json     format marker (spec version)
  controls.json, systems.json, tests.json, vendors.json, risk-register.json  ([])
  policy-index.json       one entry per scaffolded policy, pointing at the governance repo
  evidence/evidence-index.json, evidence/artifacts/
  pentest-evidence/layer1..layer4/, decision-logs/
  README.md

The command writes files only (it never runs git); existing files are left
untouched unless ``--force`` is given. Initialise both directories as git
repositories, push them, and add them as git sources.
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_TEMPLATES = os.path.join(ROOT, "policy-templates")
GOVERNANCE_TEMPLATES = os.path.join(ROOT, "templates", "governance")
EVIDENCE_REPO_FORMAT = {"format": "trust-portal-evidence-repo", "version": 1}
POLICY_NAMESPACE = uuid.UUID("6f1a2c3e-5b7d-4e9f-8a1b-2c3d4e5f6a7b")

GOVERNANCE_README = """# Governance repository

This repository holds {company}'s governance documents. The trust portal reads it
through a git source with role `governance`:

- `policies/**/*.md` - policies. Each is stored by the portal as a versioned document
  (commit, blob and SHA-256) and rendered on the public policy page of the policy whose
  `file_path` in the evidence repository's `policy-index.json` names it.
- `CLAUDE.md`, `AGENTS.md`, `README.md`, `infrastructure/**`, `agent-config/**` -
  governance documents, versioned and shown to portal admins.
- Every commit that touches those paths is recorded by the portal as a change record.

The policies start as templates: every section marked `CUSTOMIZE` must describe what the
organisation actually does before the policy is approved.
"""

EVIDENCE_README = """# Evidence repository

This repository holds {company}'s compliance data and evidence in the open layout described
by the trust portal's `docs/evidence-repo-spec.md` (format version {version}). The portal reads
it through a git source with role `evidence` and imports only what changed.

- `controls.json`, `systems.json`, `tests.json`, `vendors.json`, `risk-register.json`,
  `policy-index.json` - datasets (JSON arrays).
- `evidence/evidence-index.json` - evidence metadata; files go under `evidence/artifacts/`.
- `pentest-evidence/layer<N>/*.json` - security assessment findings, one file per scan output.
- `decision-logs/*.jsonl` - AI agent session transcripts (files over 5 MiB are split into
  parts plus a `.manifest.json`).
"""

SECTION_READMES = {
    "infrastructure/README.md": "# Infrastructure\n\nInfrastructure conventions and runbooks. "
                                "The trust portal stores every version of the files in this directory.\n",
    "agent-config/README.md": "# Agent configuration\n\nCanonical AI agent configuration "
                              "(hooks, settings). The trust portal stores every version of these files.\n",
}


def add_parser(subparsers) -> None:
    parser = subparsers.add_parser("scaffold", help="Create governance and evidence repository skeletons")
    parser.add_argument("--governance-dir", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--company", required=True, help="Legal name used in the documents")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")


def _write(path: str, content: str, force: bool, written: list[str]) -> None:
    if os.path.exists(path) and not force:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    written.append(path)


def _keep(directory: str, written: list[str]) -> None:
    os.makedirs(directory, exist_ok=True)
    marker = os.path.join(directory, ".gitkeep")
    if not os.path.exists(marker):
        open(marker, "w").close()
        written.append(marker)


def _policy_title_and_category(text: str, filename: str) -> tuple[str, str]:
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else filename
    category_match = re.search(r"^\*\*Category:\*\*\s*([A-Za-z ]+)", text, re.MULTILINE)
    category = (category_match.group(1).strip().lower().replace(" ", "_")
                if category_match else "security")
    return title, category


def scaffold(governance_dir: str, evidence_dir: str, company: str, force: bool = False) -> list[str]:
    written: list[str] = []
    year = str(datetime.now(timezone.utc).year)

    policy_index = []
    for filename in sorted(os.listdir(POLICY_TEMPLATES)):
        if not filename.endswith(".md"):
            continue
        with open(os.path.join(POLICY_TEMPLATES, filename), encoding="utf-8") as handle:
            text = handle.read()
        _write(os.path.join(governance_dir, "policies", filename), text, force, written)
        title, category = _policy_title_and_category(text, filename)
        policy_index.append({
            "id": str(uuid.uuid5(POLICY_NAMESPACE, filename)),
            "title": title,
            "category": category,
            "version": "1.0",
            "file_path": f"policies/{filename}",
            "status": "draft",
            "soc2_control_ids": [],
        })

    for template in ("CLAUDE.md.template", "AGENTS.md.template"):
        with open(os.path.join(GOVERNANCE_TEMPLATES, template), encoding="utf-8") as handle:
            text = handle.read()
        text = text.replace("{{ YEAR }}", year).replace("{{ LEGAL_ENTITY }}", company)
        _write(os.path.join(governance_dir, template.replace(".template", "")), text, force, written)
    _write(os.path.join(governance_dir, "README.md"), GOVERNANCE_README.format(company=company), force, written)
    for relative, content in SECTION_READMES.items():
        _write(os.path.join(governance_dir, relative), content, force, written)

    _write(os.path.join(evidence_dir, ".evidence-repo.json"),
           json.dumps(EVIDENCE_REPO_FORMAT, indent=2) + "\n", force, written)
    for name in ("controls.json", "systems.json", "tests.json", "vendors.json", "risk-register.json"):
        _write(os.path.join(evidence_dir, name), "[]\n", force, written)
    _write(os.path.join(evidence_dir, "policy-index.json"), json.dumps(policy_index, indent=2) + "\n",
           force, written)
    _write(os.path.join(evidence_dir, "evidence", "evidence-index.json"), "[]\n", force, written)
    _keep(os.path.join(evidence_dir, "evidence", "artifacts"), written)
    for layer in range(1, 5):
        _keep(os.path.join(evidence_dir, "pentest-evidence", f"layer{layer}"), written)
    _keep(os.path.join(evidence_dir, "decision-logs"), written)
    _write(os.path.join(evidence_dir, "README.md"),
           EVIDENCE_README.format(company=company, version=EVIDENCE_REPO_FORMAT["version"]), force, written)
    return written


def run(args, out=sys.stdout) -> int:
    written = scaffold(os.path.abspath(args.governance_dir), os.path.abspath(args.evidence_dir),
                       args.company, force=args.force)
    out.write(f"Wrote {len(written)} file(s).\n")
    out.write("Next: initialise both directories as git repositories, push them, then add them to the "
              "portal (Admin > Git sources, or `python -m cli git-source add`) with roles "
              "'governance' and 'evidence'.\n")
    return 0
