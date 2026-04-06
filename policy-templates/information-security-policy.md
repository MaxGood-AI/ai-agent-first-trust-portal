# Information Security Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security  
**SOC 2 References:** CC1.1, CC1.2, CC1.3, CC1.4, CC2.1, CC2.2, CC2.3  
**Version:** 1.0 — Draft  
**Last Review:** [Date]  

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What does your company actually build or provide? (Be specific: "We run a SaaS platform for X" not "We deliver technology solutions.")
- Who does this policy apply to? Full-time employees only? Contractors too? Interns? Vendors with system access?
- Are there any systems, environments, or teams explicitly OUT of scope? (e.g., "Marketing's WordPress site is managed by an agency and excluded from this policy.")
- Does this cover only production systems, or also development/staging environments?
-->

This policy establishes the information security program for [Organization Name]. It applies to [all employees, contractors, and third parties with access to company systems and data].

The scope of this policy covers [describe the systems, data, and environments covered].

## 2. Security Organization and Responsibilities

<!-- CUSTOMIZE:
- Who is ultimately accountable for security? Is it the CEO, a CTO, a dedicated CISO, or someone wearing multiple hats?
- Do you have a dedicated security team, or does engineering handle security as part of their role?
- If you're a small company: who actually makes security decisions day-to-day? Who gets the call at 2 AM if something breaks?
- Is there a board of directors or advisory board that receives security reports? How often?
- Who decides whether to accept a security risk vs. fix it?
-->

### Security Leadership

| Role | Person/Team | Responsibilities |
|------|-------------|-----------------|
| Security Owner | [Name/Title] | Overall accountability for security program |
| Day-to-Day Security | [Name/Title] | Operational security decisions, monitoring |
| Security Escalation | [Name/Title] | After-hours and critical incident contact |

### Reporting Structure

[Describe how security reports to leadership. For example: "The CTO reviews security metrics monthly and reports to the CEO quarterly" or "The founder handles everything and reviews security when issues come up."]

## 3. Risk Management Approach

<!-- CUSTOMIZE:
- How do you actually identify security risks today? Is it ad-hoc ("someone notices something"), periodic reviews, or a formal process?
- How often do you actually sit down and think about what could go wrong? Be honest — if it's "only when something breaks," say that.
- Do you maintain a written list of known risks? Where does it live — a spreadsheet, a ticketing system, someone's head?
- When you find a risk, how do you decide what to do about it? Is there a formal process, or does the CTO/CEO just make a call?
- Do you have cyber insurance? Does your insurer require anything specific?
-->

[Organization Name] manages information security risk by [describe your actual approach].

Risks are identified through [describe actual methods — vulnerability scanning, penetration testing, employee reporting, customer feedback, etc.].

Risk decisions are made by [who] and documented in [where].

## 4. Security Awareness and Training

<!-- CUSTOMIZE:
- What do new hires learn about security on their first day or first week? Is it a formal training, a document they read, a conversation, or nothing?
- Do employees receive ongoing security training? How often, and what format? (e.g., "Annual 30-minute video" or "Quarterly phishing simulations" or "We send a Slack message when something comes up.")
- How do you make sure people actually complete the training? Do you track it?
- Have you ever done a phishing simulation? What happened?
- Do developers get any specific security training (secure coding, OWASP, etc.)?
-->

### New Hire Security Onboarding

All new hires [describe what actually happens — e.g., "complete a 30-minute security orientation during their first week" or "read the security section of the employee handbook"].

### Ongoing Training

[Describe your actual ongoing training program, if any. If you don't have one yet, say "Security awareness training is provided ad-hoc as needs arise. A formal program is planned for [timeline]."]

### Training Records

Training completion is tracked in [system/spreadsheet/not currently tracked].

## 5. Physical Security

<!-- CUSTOMIZE:
- Where does your team work? Fully remote? An office? Co-working space? Mix?
- If you have an office: who has keys/badges? Is there a visitor sign-in? Are server rooms locked separately?
- If fully remote: do you have any requirements for home office security? (e.g., "Lock your laptop when away from desk" or "No working from coffee shops on sensitive data.")
- Where are your servers physically located? (Likely "AWS/GCP/Azure data centers" — but say so explicitly.)
- Does anyone have company equipment at home? How do you track it?
-->

### Work Locations

[Organization Name] operates as a [fully remote / hybrid / office-based] organization.

### Hosting and Data Centers

All production infrastructure is hosted in [cloud provider and region(s)]. Physical data center security is managed by [cloud provider] under their [SOC 2 / ISO 27001] certification.

### Equipment Management

Company-issued equipment [is/is not] tracked. [Describe how — asset inventory spreadsheet, MDM solution, etc.]

## 6. Compliance and Enforcement

<!-- CUSTOMIZE:
- What actually happens if someone violates this policy? Have you ever had to enforce it?
- Is there a formal disciplinary process, or would you handle it case by case?
- Do employees acknowledge this policy in writing (e.g., sign an acceptable use agreement)?
- Are there any legal or regulatory requirements specific to your industry that drive security practices? (e.g., HIPAA, PCI-DSS, GDPR, PIPEDA, state privacy laws.)
- How do you handle security policy exceptions? Can a team lead approve a temporary exception, or does it require the CEO?
-->

### Policy Violations

Violations of this policy may result in [describe actual consequences — verbal warning, written warning, termination, etc.]. Violations are handled by [who — HR, management, the security lead].

### Policy Acknowledgment

All employees [sign / electronically acknowledge / are expected to read] this policy [upon hire / annually / when updated].

### Regulatory Requirements

[Organization Name] is subject to the following regulatory requirements that influence this security program: [list actual regulations — e.g., GDPR, SOC 2, PIPEDA, or "none beyond SOC 2 at this time"].

### Policy Exceptions

Exceptions to this policy require approval from [who] and must be documented in [where]. Exceptions are reviewed [how often] and expire after [time period / "they don't expire currently"].

## 7. Review Schedule

<!-- CUSTOMIZE:
- How often will you realistically review this policy? Annually is the SOC 2 minimum, but be honest about what you'll actually do.
- Who will be responsible for triggering the review?
- What would cause an out-of-cycle review? (e.g., a security incident, a major infrastructure change, a new regulation.)
-->

This policy is reviewed [annually / semi-annually / quarterly] or when triggered by:

- A significant security incident
- Major changes to infrastructure or business operations
- New regulatory requirements
- [Other triggers relevant to your organization]

The next scheduled review is [date].

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
