# Change Management Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security  
**SOC 2 References:** CC8.1  
**Version:** 1.0 — Draft  
**Last Review:** [Date]  

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What kinds of changes does this policy cover? Just code changes, or also infrastructure changes (new servers, DNS changes, database migrations)? What about configuration changes (environment variables, feature flags)?
- Does this apply to all environments (dev, staging, production) or only production?
- Are there any systems where changes happen outside this process? (e.g., "Marketing updates the website directly via WordPress" or "The CEO sometimes changes DNS records.")
- Does this cover changes made by AI coding agents? If so, how are those reviewed?
-->

This policy governs how changes to [Organization Name]'s production systems, code, infrastructure, and configurations are requested, reviewed, approved, and deployed.

This policy applies to [all changes to production systems / all code changes regardless of environment / describe actual scope].

### Repository Scope

Every repository holding code of a customer-facing system or of a system that processes customer data is in scope. The repositories the risk register designates as neither customer-facing nor processing customer data are out of scope: [list them, or "none"].

### Change Types

| Change Type | Examples | Covered by This Policy? |
|-------------|----------|------------------------|
| Code changes | New features, bug fixes, refactors | [Yes/No] |
| Infrastructure changes | New servers, scaling, network changes | [Yes/No] |
| Configuration changes | Environment variables, feature flags | [Yes/No] |
| Database changes | Schema migrations, data fixes | [Yes/No] |
| Third-party integrations | New SaaS tools, API integrations | [Yes/No] |

## 2. Change Request Process

<!-- CUSTOMIZE:
- How do changes actually get requested and tracked? Do you use an issue tracker, a task board, sticky notes, or chat messages?
- Who can request a change? Anyone on the team, or only certain roles?
- What information is required in a change request? Just a title, or a full description with acceptance criteria?
- Is there a formal approval step before work begins, or do developers just pick up work and start?
- If you use AI coding agents: how are AI-generated changes tracked? Do they create their own tickets, or work from existing ones?
-->

### Tracking System

Changes are tracked in [tool name — e.g., your issue tracker or task board]. [Describe how work items flow — e.g., "Cards move from Backlog to In Progress to Review to Done."]

### Change Request Requirements

Every change request must include:
- [ ] [Description of the change]
- [ ] [Reason for the change]
- [ ] [Impact assessment — what could break?]
- [ ] [Add/remove items to match what you actually require]

### Approval Process

Each change is approved by the change-approval control in section 4. [Describe any approval before work begins — e.g., "the product owner approves the plan on the work item before work begins" or "the CEO approves all significant changes before work begins".]

## 3. Development Standards

### Branching Strategy

<!-- CUSTOMIZE:
- What is the main branch of each repository called (`main`, `master`)?
- Who can push to the main branch, and through which credentials?
- Do you deploy directly from the main branch, or from release tags?
-->

[Organization Name] pushes every change directly to the main branch (`[main]`) of its repository once the change-approval control in section 4 has passed. Each commit message records the change in `## Problem`, `## Solution` and `## Verified` sections.

Push access to the main branch: [who — e.g., "the engineering team and the AI agents working for them, through [credential mechanism]"].

### Coding Standards

<!-- CUSTOMIZE:
- Do you have documented coding standards? Where do they live?
- Do you use linters or formatters? Which ones, and are they enforced automatically (CI) or manually?
- Are there language-specific or framework-specific conventions your team follows?
- Do AI-generated code changes follow the same standards?
-->

[Describe actual coding standards, or note "Coding standards are documented in [location]" or "Coding standards are informal and enforced through code review."]

Automated enforcement:
- Linters: [list tools — e.g., ESLint, Pylint, Flake8, or "none"]
- Formatters: [list tools — e.g., Prettier, Black, or "none"]
- Enforcement: [CI pipeline / pre-commit hooks / manual / not enforced]

## 4. Change Approval

<!-- CUSTOMIZE:
- Which AI agent performs the independent red-team review, and on which model? It runs on a different model from the one that made the change.
- Which automated security scan runs, and when (pre-commit, pre-push, CI)?
- Who is the accountable human who gives the "done." verification, for each repository or change type?
- Where is each step's evidence recorded (decision log, work item, scan output location)?
- Who may authorize skipping a step, and where is the skip recorded?
-->

### Change-Approval Control

Every change to [all code in scope / describe scope] passes three steps before it is pushed to the main branch, and each step is recorded as evidence:

| Step | What happens | Performed by | Evidence |
|------|--------------|--------------|----------|
| Independent AI red-team review | An AI agent running on a different model from the one that made the change reviews the change and its tests as an adversary and gives a PASS or FAIL verdict | [review agent and model — e.g., "OpenAI Codex"] | [where the findings and verdict are recorded — e.g., "the work item and the decision log"] |
| Automated security scan | [scan tool] scans the change for vulnerabilities and committed secrets | [when it runs — e.g., "a pre-push hook"] | [where the scan result is stored] |
| "done." verification | The accountable human tests the change, smoke-tests the likely regressions and replies "done." | [role — e.g., "the product owner"] | The decision log (the AI agent session transcript) |

A change is pushed to the main branch once all three steps have passed.

### Review Checklist

The red-team review verifies:
- [ ] [Code functions correctly]
- [ ] [Tests are included and pass]
- [ ] [No secrets or credentials in the code]
- [ ] [Add/remove items to match what the review actually checks]

### Authorized Skips

A step is skipped only with the authorization of [who — e.g., "the CTO"]. Each skip is recorded with its reason and its authorizer in [where — e.g., "the commit message and the work item"].

## 5. Testing Requirements

<!-- CUSTOMIZE:
- What testing actually happens before code reaches production? Unit tests? Integration tests? Manual testing? End-to-end tests? None?
- Is there a minimum test coverage requirement? If so, is it enforced automatically?
- Do you have a staging or QA environment where changes are tested before production? How closely does it mirror production?
- Who does the testing — the developer, a QA person, or automated CI?
- Are there any types of changes that skip testing? (e.g., "Documentation changes" or "Hotfixes get tested in production.")
- Do AI-generated tests count as sufficient test coverage, or do humans verify AI test quality?
-->

### Test Requirements by Change Type

| Change Type | Required Testing | Who Tests |
|-------------|-----------------|-----------|
| New features | [e.g., Unit tests + manual QA] | [e.g., Developer + QA] |
| Bug fixes | [e.g., Regression test for the bug] | [e.g., Developer] |
| Infrastructure | [e.g., Deploy to staging first] | [e.g., CTO] |
| Configuration | [e.g., Verify in staging] | [e.g., Developer] |

### Test Coverage

[Describe your actual test coverage situation — e.g., "We target 80% code coverage, enforced by CI" or "We have some unit tests but no formal coverage requirement" or "Testing is primarily manual."]

### Staging Environment

[Describe your staging environment — e.g., "We have a staging environment that mirrors production" or "We test locally and deploy directly to production" or "We use feature flags to test in production."]

## 6. Deployment Process

<!-- CUSTOMIZE:
- Walk through how code actually gets from "pushed to the main branch" to "running in production." Be specific.
- Is deployment automated (CI/CD) or manual? What tools do you use (GitHub Actions, AWS CodePipeline, Jenkins, manual SSH and deploy)?
- Who can trigger a deployment? Anyone, or only certain people?
- Do you deploy continuously (every push to the main branch goes to production), on a schedule, or manually when someone decides to?
- Do you have rollback procedures? Have you ever had to roll back a deployment? What happened?
- Is there any monitoring or verification after deployment? (e.g., "We check error rates for 30 minutes after deploy.")
-->

### Deployment Pipeline

1. [Describe step 1 — e.g., "Once the change-approval control has passed, the change is pushed to the main branch."]
2. [Describe step 2 — e.g., "CI pipeline runs tests and builds a Docker image."]
3. [Describe step 3 — e.g., "Image is deployed to staging for smoke testing."]
4. [Describe step 4 — e.g., "After 24 hours in staging, production deployment is triggered manually by the CTO."]

### Deployment Tools

| Tool | Purpose |
|------|---------|
| [e.g., AWS CodePipeline] | [e.g., CI/CD orchestration] |
| [e.g., Docker / ECS] | [e.g., Container deployment] |
| [Add rows for each tool] | |

### Rollback Procedure

If a deployment causes issues:

1. [Describe what actually happens — e.g., "Revert the commit on the main branch and redeploy" or "Roll back to the previous ECS task definition" or "We don't have a formal rollback process yet."]

### Post-Deployment Verification

After deployment, [describe what actually happens — e.g., "the deployer monitors error logs for 15 minutes" or "automated health checks verify the service is responding" or "nothing formal — we rely on users to report issues"].

## 7. Emergency Changes

<!-- CUSTOMIZE:
- What counts as an emergency? A production outage? A security vulnerability? A customer-facing bug? All of the above?
- What process is actually followed for emergency changes? Which steps of the change-approval control may be deferred? Testing?
- Who can authorize an emergency change?
- How are emergency changes documented after the fact? Is there a post-incident review?
- How often do emergency changes actually happen? Monthly? Quarterly? Rarely?
-->

### Definition of Emergency

An emergency change is defined as [describe — e.g., "any change required to restore production service or patch an actively exploited security vulnerability"].

### Emergency Process

Emergency changes may defer [describe what's deferred — e.g., "the independent AI red-team review" or "staging deployment" or "nothing — all changes follow the same process"]. A deferred step is an authorized skip (section 4), recorded with its reason and its authorizer.

Emergency changes require:
- [ ] Approval from [who — e.g., CTO or CEO]
- [ ] [Any other minimum requirements]
- [ ] Post-deployment documentation within [timeframe — e.g., 24 hours / next business day]
- [ ] Retroactive independent AI red-team review within [timeframe]

### Post-Emergency Documentation

After an emergency change, the following must be completed within [timeframe]:
- [Describe what documentation is required — incident report, retroactive red-team review, change record update, etc.]

## 8. Review Schedule

<!-- CUSTOMIZE:
- How often will you review this policy? Annually is the SOC 2 minimum.
- Should this policy review be aligned with any other reviews (e.g., your development process retrospective)?
-->

This policy is reviewed [annually / semi-annually] or when triggered by:

- A failed deployment or production incident caused by a change management gap
- Significant changes to development tools or processes
- Changes to team size or structure
- Audit findings related to change management

The next scheduled review is [date].

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
