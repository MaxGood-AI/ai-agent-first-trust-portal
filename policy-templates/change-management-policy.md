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
- How do changes actually get requested and tracked? Do you use Jira, Linear, GitHub Issues, KanbanZone, Trello, sticky notes, or Slack messages?
- Who can request a change? Anyone on the team, or only certain roles?
- What information is required in a change request? Just a title, or a full description with acceptance criteria?
- Is there a formal approval step before work begins, or do developers just pick up work and start?
- If you use AI coding agents: how are AI-generated changes tracked? Do they create their own tickets, or work from existing ones?
-->

### Tracking System

Changes are tracked in [tool name — e.g., KanbanZone, Jira, GitHub Issues]. [Describe how work items flow — e.g., "Cards move from Backlog to In Progress to Review to Done."]

### Change Request Requirements

Every change request must include:
- [ ] [Description of the change]
- [ ] [Reason for the change]
- [ ] [Impact assessment — what could break?]
- [ ] [Add/remove items to match what you actually require]

### Approval Process

Changes are approved by [describe — e.g., "the team lead before work begins" or "no formal pre-approval; review happens at the PR stage" or "the CEO reviews all significant changes"].

## 3. Development Standards

### Branching Strategy

<!-- CUSTOMIZE:
- What branching model do you actually use? Git Flow, GitHub Flow (feature branches off main), trunk-based development, or something else?
- Do you use feature branches? How are they named?
- Is there a protected main/production branch? Who can merge to it?
- Do you use release branches, or do you deploy directly from main?
-->

[Organization Name] uses [describe actual branching strategy — e.g., "feature branches off the main branch. Each feature branch is named with a prefix describing the change type (e.g., feature/, fix/, chore/)."].

Protected branches:
- `main` / `master`: [describe protections — e.g., "requires PR approval, no direct pushes" or "direct pushes are allowed by the CTO"]

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

## 4. Code Review Requirements

<!-- CUSTOMIZE:
- Are code reviews required for all changes? Or only for certain types (e.g., "all production changes" but not "documentation updates")?
- How many reviewers are required? Is it one person, two people, or "whoever is available"?
- Who is qualified to review? Any developer, or only senior developers / the CTO?
- What does a reviewer actually check? Functionality? Style? Security? Tests? Or just a quick "looks fine"?
- How long do reviews typically take? Minutes, hours, days?
- Can the author merge their own PR after approval, or does someone else merge it?
- If AI agents generate code: does AI-generated code get the same review, more review, or less review than human-written code?
- Can the CEO or CTO bypass code review in urgent situations?
-->

### Review Process

All changes to [production code / all code / describe scope] require [a code review via pull request / peer review / describe actual process].

| Requirement | Standard Changes | [Other category if applicable] |
|-------------|-----------------|-------------------------------|
| Reviewers required | [1 / 2 / varies] | [number] |
| Who can review | [Any developer / Senior devs only / CTO] | [who] |
| Who can merge | [Reviewer / Author after approval / CTO only] | [who] |

### Review Checklist

Reviewers verify:
- [ ] [Code functions correctly]
- [ ] [Tests are included and pass]
- [ ] [No secrets or credentials in the code]
- [ ] [Add/remove items to match what reviewers actually check]

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
- Walk through how code actually gets from "merged PR" to "running in production." Be specific.
- Is deployment automated (CI/CD) or manual? What tools do you use (GitHub Actions, AWS CodePipeline, Jenkins, manual SSH and deploy)?
- Who can trigger a deployment? Anyone, or only certain people?
- Do you deploy continuously (every merge goes to production), on a schedule, or manually when someone decides to?
- Do you have rollback procedures? Have you ever had to roll back a deployment? What happened?
- Is there any monitoring or verification after deployment? (e.g., "We check error rates for 30 minutes after deploy.")
-->

### Deployment Pipeline

1. [Describe step 1 — e.g., "Developer merges PR to main branch."]
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

1. [Describe what actually happens — e.g., "Revert the merge commit and redeploy" or "Roll back to the previous ECS task definition" or "We don't have a formal rollback process yet."]

### Post-Deployment Verification

After deployment, [describe what actually happens — e.g., "the deployer monitors error logs for 15 minutes" or "automated health checks verify the service is responding" or "nothing formal — we rely on users to report issues"].

## 7. Emergency Changes

<!-- CUSTOMIZE:
- What counts as an emergency? A production outage? A security vulnerability? A customer-facing bug? All of the above?
- What process is actually followed for emergency changes? Can someone deploy without a code review? Without tests?
- Who can authorize an emergency change?
- How are emergency changes documented after the fact? Is there a post-incident review?
- How often do emergency changes actually happen? Monthly? Quarterly? Rarely?
-->

### Definition of Emergency

An emergency change is defined as [describe — e.g., "any change required to restore production service or patch an actively exploited security vulnerability"].

### Emergency Process

Emergency changes may bypass [describe what's bypassed — e.g., "the standard code review process" or "staging deployment" or "nothing — all changes follow the same process"].

Emergency changes require:
- [ ] Approval from [who — e.g., CTO or CEO]
- [ ] [Any other minimum requirements]
- [ ] Post-deployment documentation within [timeframe — e.g., 24 hours / next business day]
- [ ] Retroactive code review within [timeframe]

### Post-Emergency Documentation

After an emergency change, the following must be completed within [timeframe]:
- [Describe what documentation is required — incident report, retroactive PR, change record update, etc.]

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
