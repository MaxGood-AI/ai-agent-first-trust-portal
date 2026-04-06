# Access Control Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security  
**SOC 2 References:** CC6.1, CC6.2, CC6.3, CC6.4, CC6.5, CC6.6, CC6.7, CC6.8  
**Version:** 1.0 — Draft  
**Last Review:** [Date]  

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What systems and applications does this policy cover? List your actual stack: AWS console, GitHub, Slack, your production database, your SaaS tools, etc.
- Does this cover customer-facing access (end users logging into your product) or only internal team access? Or both?
- Are there any systems where access is managed by a third party and outside your direct control? (e.g., "Our accountant manages QuickBooks access.")
-->

This policy governs how access to [Organization Name]'s systems, applications, and data is granted, managed, and revoked. It applies to [all employees, contractors, and third-party users who access company systems].

### Systems in Scope

| System | Type | Access Managed By |
|--------|------|-------------------|
| [e.g., AWS Console] | Cloud Infrastructure | [e.g., CTO] |
| [e.g., GitHub] | Source Code | [e.g., Engineering Lead] |
| [e.g., Production Database] | Data Store | [e.g., CTO] |
| [Add rows for each system] | | |

## 2. User Account Management

### Provisioning (Granting Access)

<!-- CUSTOMIZE:
- Walk through what actually happens on a new hire's first day. Who creates their accounts? Is there a checklist, or does someone just remember what to set up?
- How do you decide what level of access a new person gets? Does everyone get the same access, or does it depend on their role?
- Who approves access requests? Is it the hiring manager, the CTO, or does the person setting up accounts just decide?
- How long does it take from hire date to having all accounts ready? Same day? A few days?
- What about contractors — do they get the same access as employees, or is it more limited?
-->

New user accounts are provisioned as follows:

1. [Describe the actual trigger — e.g., "HR notifies the CTO via email/Slack when a new hire is confirmed."]
2. [Describe who creates accounts and in what systems.]
3. [Describe how access level is determined — role-based, copied from similar employee, etc.]
4. [Describe the approval process, if any.]

### Deprovisioning (Removing Access)

<!-- CUSTOMIZE:
- When someone leaves the company (voluntarily or involuntarily), what actually happens to their accounts? Walk through the steps.
- How quickly are accounts disabled? Same day? Within 24 hours? When someone remembers?
- Who is responsible for deprovisioning — HR, the manager, IT, the CTO doing it themselves?
- Do you have a checklist of all accounts to disable, or does someone go from memory?
- What about shared accounts or API keys that a departing person knew about?
- Have you ever had a situation where a former employee still had access? What happened?
-->

When an employee or contractor departs:

1. [Describe the actual trigger — e.g., "HR sends a termination notice to the CTO."]
2. [Describe what gets disabled first and how quickly — e.g., "Email and Slack are disabled within 4 hours."]
3. [Describe the full deprovisioning checklist, or note that one needs to be created.]

**Target timeline:** All access is revoked within [24 hours / same business day / other realistic timeline] of departure.

### Account Modifications

<!-- CUSTOMIZE:
- When someone changes roles internally, how is their access updated? Do they keep old access and get new access added (access creep), or is it reviewed?
- Who requests access changes for role transitions?
-->

When an employee changes roles, [describe what actually happens — e.g., "their manager submits a request to IT" or "it's handled ad-hoc as needs come up"].

## 3. Authentication Requirements

### Multi-Factor Authentication (MFA)

<!-- CUSTOMIZE:
- Which systems require MFA today? Be specific. Not "all systems" unless you actually enforce MFA on everything.
- What MFA methods do you support? Hardware keys, authenticator apps, SMS? Be honest — if some people use SMS, say so.
- Are there any systems where MFA is available but not required? Why?
- Is MFA enforced technically (you literally cannot log in without it) or is it policy-only (you should use it but technically can skip it)?
-->

MFA is required for the following systems:

| System | MFA Enforced? | Method |
|--------|--------------|--------|
| [e.g., AWS Console] | [Yes — technically enforced / Policy only] | [e.g., Authenticator app] |
| [e.g., GitHub] | [Yes/No] | [e.g., Hardware key or authenticator app] |
| [Add rows] | | |

### Password Requirements

<!-- CUSTOMIZE:
- What are your actual password requirements? If you use SSO and don't have separate passwords for most things, say that.
- Do you use a password manager? Is it required or recommended? Which one?
- If you have password requirements (length, complexity), are they technically enforced or just policy?
- How do people reset forgotten passwords?
-->

[Organization Name] [uses SSO via [provider] for most systems / requires individual passwords for each system].

Password requirements (where applicable):
- Minimum length: [number] characters
- Complexity requirements: [describe, or "none — we rely on length"]
- Password manager: [required / recommended / not used] — [name of tool]

### Single Sign-On (SSO)

<!-- CUSTOMIZE:
- Do you use an SSO provider (Google Workspace, Okta, Azure AD, etc.)? Which systems are connected to it?
- Are there systems that should be on SSO but aren't yet?
-->

[Organization Name] [uses / does not use] SSO. [If yes: "The SSO provider is [name] and the following systems are connected: [list]."]

## 4. Authorization and Least Privilege

<!-- CUSTOMIZE:
- Do you actually follow least privilege, or does everyone have admin access to everything? Be honest — it's better to document what you do and plan improvements than to write a policy you don't follow.
- Do you use role-based access (defined roles with specific permissions) or is it more ad-hoc?
- For your cloud infrastructure (AWS/GCP/Azure): do developers have production access? Can everyone deploy, or only certain people?
- For your source code: can everyone merge to main, or are there branch protections?
- Who has access to customer data directly (database access, admin panels, etc.)?
-->

Access is granted based on [role-based access control / ad-hoc assignment based on job needs / "everyone currently has broad access and we are working to tighten it"].

### Role Definitions

| Role | Systems Access | Approximate # of People |
|------|---------------|------------------------|
| [e.g., Developer] | [e.g., GitHub, staging AWS, CI/CD] | [number] |
| [e.g., Admin/Infrastructure] | [e.g., Production AWS, databases, all systems] | [number] |
| [e.g., Non-technical staff] | [e.g., Email, Slack, Google Drive] | [number] |

## 5. Privileged Access Management

<!-- CUSTOMIZE:
- Who has root/admin access to your production systems? How many people? Name the roles, not the people.
- How are privileged credentials (root passwords, admin API keys, database passwords) stored? In a password manager? In environment variables? In someone's head?
- Do privileged accounts have additional controls (separate MFA, shorter session timeouts, audit logging)?
- Are there any shared admin accounts (e.g., a shared "admin@company.com" login)? If so, who has the password?
- How are secrets and API keys managed? (e.g., AWS Secrets Manager, HashiCorp Vault, .env files, or "they're in a shared password manager.")
-->

### Privileged Accounts

The following roles have privileged (admin-level) access:

| Role | What They Can Access | # of People | Controls |
|------|---------------------|-------------|----------|
| [e.g., AWS Root Account] | [Everything] | [1-2] | [e.g., MFA required, rarely used] |
| [e.g., Database Admin] | [Production data] | [number] | [e.g., Access via bastion host only] |

### Credential Storage

Privileged credentials are stored in [describe actual storage — password manager name, AWS Secrets Manager, etc.].

Shared accounts [exist / do not exist]. [If they exist, list them and explain why.]

## 6. Remote Access

<!-- CUSTOMIZE:
- How does your team access production systems remotely? VPN? Direct SSH? Cloud console through a browser?
- Are there any restrictions on where or how people can access systems? (e.g., "Only from company devices" or "From anywhere — we're fully remote and trust our team.")
- Do you use a bastion host or jump box for production access?
- Can people access company systems from personal devices? Is that an official policy or just what happens?
-->

[Organization Name] is a [fully remote / hybrid / office-based] organization. Remote access to production systems is managed as follows:

- **Production infrastructure:** Accessed via [VPN / bastion host / cloud console / direct SSH — describe what actually happens].
- **Source code:** Accessed via [GitHub/GitLab from any device / only company devices].
- **Internal tools:** Accessed via [browser with SSO / VPN required / no restrictions].

### Device Requirements

[Describe any actual device requirements — e.g., "Company-issued laptops only" or "Personal devices are allowed with full-disk encryption" or "No device requirements are currently enforced."]

## 7. Access Reviews

<!-- CUSTOMIZE:
- Do you currently review who has access to what? How often? Be honest — if you've never done a formal access review, say so and commit to a schedule.
- Who conducts the reviews? The CEO? Each team lead? IT?
- What happens when the review finds someone with access they shouldn't have?
- How do you document that the review happened? (This is what auditors will ask for.)
-->

Access reviews are conducted [quarterly / semi-annually / annually / "we have not yet conducted a formal access review — the first is scheduled for [date]"].

### Review Process

1. [Describe who generates the list of users and their access levels.]
2. [Describe who reviews the list and confirms each person's access is appropriate.]
3. [Describe how unnecessary access is removed.]
4. [Describe how the review is documented / where records are kept.]

### Review Scope

Each review covers:
- [Active user accounts across all in-scope systems]
- [Privileged access holders]
- [Service accounts and API keys]
- [Contractor and third-party access]

## 8. Review Schedule

<!-- CUSTOMIZE:
- How often will you realistically review this policy? Annually is the SOC 2 minimum.
- Is this review tied to your access review schedule, or separate?
-->

This policy is reviewed [annually / semi-annually] or when triggered by:

- A security incident involving unauthorized access
- Significant changes to systems or infrastructure
- Organizational changes (acquisitions, large hiring waves, layoffs)
- Changes to regulatory requirements

The next scheduled review is [date].

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
