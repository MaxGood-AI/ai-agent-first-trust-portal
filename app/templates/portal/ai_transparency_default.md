# AI-Driven Compliance: Our Approach

## How We Use AI in Compliance

This organization uses AI agents as formal participants in its compliance and software development processes. This page explains how AI is governed, how its work is verified, and how it contributes to our compliance posture.

## AI Agents as Organizational Actors

AI coding agents (such as Anthropic's Claude Code and OpenAI's Codex) operate under formal governance policies. These governance documents define:

- What actions agents can and cannot take
- Required approval workflows for different types of changes
- Security and data handling requirements
- Code quality and testing standards

These governance documents are version-controlled and treated as formal policy for SOC 2 purposes.

## Evidence Chain

Every AI agent interaction produces a traceable evidence chain:

1. **Decision Logs** — Complete session transcripts of AI agent interactions are captured and stored as compliance evidence. These show exactly what was discussed, decided, and implemented.

2. **Change Approval** — Work items are tracked on a kanban board. Approved implementation plans are documented on each card before work begins, providing design review evidence.

3. **Human Verification** — After AI agents complete work, a human reviewer tests the changes. This formal verification is recorded in the session transcript.

4. **Independent Code Review** — Before final commits, an independent AI agent from a different provider reviews the code and tests. Findings are documented as part of the change record.

5. **Structured Commits** — All code changes include structured commit messages explaining the problem, solution, and verification steps.

## Human Oversight

AI agents operate under human supervision at all times:

- All AI-generated code changes require human approval before deployment
- AI agents cannot access production systems directly
- Compliance-critical decisions require explicit human sign-off
- AI governance policies are reviewed and updated by the compliance team

## Transparency Commitment

We believe that transparency about AI usage builds trust. By documenting our AI governance practices and making them part of our compliance program, we demonstrate that AI-assisted development can meet the same rigor expected of traditional development processes.

For questions about our AI governance practices, contact us through the information provided on this portal.
