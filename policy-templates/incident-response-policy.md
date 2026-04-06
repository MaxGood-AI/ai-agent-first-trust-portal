# Incident Response Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security  
**SOC 2 References:** CC7.2, CC7.3, CC7.4, CC7.5  
**Version:** 1.0 — Draft  
**Last Review:** [Date]  

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What does "incident" mean to your organization? Is it only security breaches, or does it include availability issues (outages), data quality issues, or compliance violations?
- Does this policy cover incidents involving customer data, internal systems only, or both?
- Does this apply to all systems and services, or only production? What about incidents in your development or staging environments?
- If you use third-party services and they have an incident that affects your customers, is that in scope?
-->

This policy defines how [Organization Name] identifies, responds to, and recovers from security incidents. It applies to [all employees, contractors, and third-party service providers who discover or are involved in responding to incidents].

An incident is defined as [describe — e.g., "any event that compromises the confidentiality, integrity, or availability of company systems or customer data" or "any unplanned disruption to production services"].

## 2. Incident Classification

<!-- CUSTOMIZE:
- Have you ever had a security incident? What was it and how did you respond? That real experience should inform these severity levels.
- What would count as a Severity 1 (drop everything) at your company? Complete production outage? Customer data breach? Both?
- What's the threshold between "something we should look at soon" and "wake someone up at 2 AM"?
- Do you have an on-call rotation, or is there one person who handles everything?
- How many customers or how much revenue would need to be affected to escalate severity?
-->

### Severity Levels

| Severity | Definition | Response Time | Examples |
|----------|-----------|---------------|----------|
| **Sev 1 — Critical** | [Define in your own terms — e.g., "Complete production outage affecting all customers" or "Confirmed breach of customer data"] | [e.g., Immediately — within 15 minutes] | [List 2-3 concrete examples relevant to your business] |
| **Sev 2 — High** | [e.g., "Partial outage affecting a significant portion of customers" or "Suspected unauthorized access to sensitive systems"] | [e.g., Within 1 hour during business hours, within 4 hours after hours] | [Concrete examples] |
| **Sev 3 — Medium** | [e.g., "Degraded service performance" or "Security vulnerability discovered but not exploited"] | [e.g., Within 1 business day] | [Concrete examples] |
| **Sev 4 — Low** | [e.g., "Minor security policy violation" or "Failed login attempts below threshold"] | [e.g., Within 1 week / next scheduled review] | [Concrete examples] |

### Escalation Thresholds

- Sev 1 and Sev 2 are automatically escalated to [who — CEO, CTO, full team].
- Sev 3 incidents are handled by [who — on-call engineer, security lead].
- Sev 4 incidents are logged and reviewed [when — weekly, monthly, during regular meetings].

## 3. Detection and Reporting

<!-- CUSTOMIZE:
- How would you actually find out about a security incident today? Think through each scenario:
  - A customer reports something is broken or their data was exposed — how do they reach you? Support email? Chat? Phone?
  - Your monitoring system detects something — what monitoring do you actually have? CloudWatch? Datadog? Application logs? Uptime checks? Or nothing automated?
  - An employee notices something suspicious — where do they report it? Slack channel? Email to the CTO? There's no defined process?
  - A third-party security researcher finds a vulnerability — do you have a way for them to contact you? A security.txt file? A bug bounty program?
- Who is responsible for triaging incoming reports and deciding the severity?
- Is there a single place where all incidents are logged, or do they end up scattered across Slack messages and emails?
-->

### Detection Sources

| Source | What It Detects | Who Monitors |
|--------|----------------|-------------|
| [e.g., CloudWatch Alarms] | [e.g., Service downtime, error rate spikes] | [e.g., Automated — alerts to Slack] |
| [e.g., Application Logs] | [e.g., Authentication failures, application errors] | [e.g., Reviewed ad-hoc / daily] |
| [e.g., Customer Reports] | [e.g., Bugs, data issues, suspicious activity] | [e.g., Support team / CEO] |
| [e.g., Employee Reports] | [e.g., Suspicious emails, unusual system behavior] | [e.g., Reported to CTO via Slack] |
| [Add actual detection sources] | | |

### Reporting Channels

Anyone who suspects a security incident should:

1. [Describe the primary reporting channel — e.g., "Post in the #security-incidents Slack channel" or "Email security@company.com" or "Call/text the CTO directly."]
2. [Describe what information to include — e.g., "What happened, when, what systems are affected, and any evidence (screenshots, logs)."]
3. [Describe urgency expectations — e.g., "For Sev 1/2, also call [phone number]. Do not wait for a Slack response."]

### External Reporting

Security researchers and external parties can report vulnerabilities via [describe — e.g., "security@company.com" or "We don't currently have a public reporting channel — establishing one is planned for [date]."]

## 4. Response Procedures

<!-- CUSTOMIZE:
- When an incident is confirmed, what actually happens? Walk through a realistic scenario.
- Who takes charge? Is there a designated incident commander, or is it whoever is available?
- How do you communicate during an incident? A dedicated Slack channel? A video call? Phone?
- Do you communicate with affected customers during an incident? How and when?
- If you have a status page, who updates it?
- Do you have any runbooks or documented procedures for common incident types (e.g., "what to do if AWS goes down")?
-->

### Incident Response Roles

| Role | Responsibility | Assigned To |
|------|---------------|-------------|
| Incident Commander | Overall coordination and decision-making | [e.g., CTO or most senior available engineer] |
| Technical Lead | Investigation and technical remediation | [e.g., Senior developer] |
| Communications Lead | Customer and stakeholder communication | [e.g., CEO or customer success lead] |

### Response Steps

Upon confirmation of an incident:

1. **Acknowledge** — The incident commander [is automatically assigned / is the first responder / is contacted by whoever discovers the incident].
2. **Assess** — Determine severity level using the classification table above.
3. **Assemble** — For Sev 1/2: [describe how the response team is assembled — e.g., "Start a dedicated Slack channel and video call" or "Call the team via phone."]
4. **Communicate** — [Describe initial communication — e.g., "Post in #incidents channel and notify leadership" or "CEO sends email to affected customers within [timeframe]."]
5. **Begin containment** — See Section 5.

### Customer Communication

<!-- CUSTOMIZE:
- Do you notify customers about incidents? At what severity level?
- How quickly do you communicate? What channel (email, status page, in-app notification)?
- Who drafts and approves customer communications?
- Do you have a status page? Where is it hosted?
-->

Customers are notified of incidents at [Sev 1 / Sev 1 and Sev 2 / all severity levels] via [email / status page / in-app notification / describe actual channel].

Customer communications are [drafted by X and approved by Y / sent directly by the CEO / handled ad-hoc].

## 5. Investigation and Containment

<!-- CUSTOMIZE:
- When an incident is happening, how do you investigate? Who has access to the logs and systems needed to investigate?
- How do you contain an incident? Can you isolate a compromised server? Revoke API keys quickly? Block an IP address? Or would you need to figure it out in the moment?
- Do you preserve evidence (logs, snapshots) before making changes? Or do you fix first and investigate later?
- Have you ever needed to engage external help (forensics firm, AWS support, law enforcement)? Do you have contacts ready?
-->

### Investigation

The technical lead investigates by:

1. [Describe actual investigation steps — e.g., "Review application and infrastructure logs in CloudWatch" or "Check access logs for unauthorized activity."]
2. [Describe how evidence is preserved — e.g., "Take snapshots of affected systems before making changes" or "Export relevant logs to a secure location."]

### Containment

Depending on the incident type, containment may include:

- [e.g., Revoking compromised credentials or API keys]
- [e.g., Isolating affected systems from the network]
- [e.g., Blocking malicious IP addresses]
- [e.g., Disabling compromised user accounts]
- [Add containment actions relevant to your infrastructure]

### Evidence Preservation

Before containment actions that modify systems, the following evidence is preserved:
- [e.g., System logs exported to secure storage]
- [e.g., Database snapshots taken]
- [e.g., Screenshots of unusual activity]
- [Describe what you would actually preserve, or note "Evidence preservation procedures need to be established."]

## 6. Eradication and Recovery

<!-- CUSTOMIZE:
- After containing an incident, how do you remove the threat? (e.g., patching a vulnerability, removing malware, rotating all credentials.)
- How do you restore service? Do you redeploy from clean images, restore from backups, or fix in place?
- How do you verify that the threat is actually gone before restoring normal operations?
- Do you have tested backups? When was the last time you actually restored from a backup?
- How long does recovery typically take? What's your target?
-->

### Eradication

Once the incident is contained:

1. [Describe how the root cause is removed — e.g., "Patch the vulnerability" or "Rotate all potentially compromised credentials" or "Rebuild affected systems from clean images."]
2. [Describe verification — e.g., "Scan systems to confirm the vulnerability is patched" or "Monitor logs for recurrence."]

### Recovery

Service is restored by:

1. [Describe recovery steps — e.g., "Redeploy from the last known good container image" or "Restore database from backup."]
2. [Describe verification — e.g., "Run automated health checks" or "Manually verify key functionality."]
3. [Describe monitoring — e.g., "Enhanced monitoring for 72 hours post-recovery."]

### Backup and Restore

- Backups are [taken automatically every X hours / daily / describe actual backup schedule].
- Backups are stored in [location — e.g., AWS S3 with cross-region replication].
- Last tested restore: [date, or "backups have not been test-restored — this is a known gap"].

## 7. Post-Incident Review

<!-- CUSTOMIZE:
- Do you conduct post-mortems after incidents? Be honest — if you've never done one, that's okay but plan for it.
- Who participates in post-incident reviews? Just the responders, or the broader team?
- How soon after the incident does the review happen?
- Do you document lessons learned? Where?
- Do you track follow-up action items to completion?
- Is the review blame-free? Do you explicitly follow a blameless post-mortem culture?
-->

### Review Process

A post-incident review is conducted for all [Sev 1 and Sev 2 incidents / all incidents / incidents that affected customers] within [48 hours / 1 week / describe realistic timeline] of resolution.

The review includes:
1. **Timeline reconstruction** — What happened and when.
2. **Root cause analysis** — Why it happened (using [5 Whys / fishbone diagram / informal discussion]).
3. **Response evaluation** — What went well and what could be improved in the response process.
4. **Action items** — Concrete steps to prevent recurrence, with owners and deadlines.

### Documentation

Post-incident reports are documented in [describe location — e.g., "a shared Google Doc folder" or "the incident tracking system" or "we plan to document in [location]"].

Reports include:
- Incident summary and timeline
- Root cause analysis
- Impact assessment (customers affected, duration, data involved)
- Remediation actions taken
- Prevention recommendations

### Blameless Culture

[Organization Name] [follows / commits to following] a blameless post-mortem approach. The goal is to improve systems and processes, not to assign blame to individuals.

## 8. Breach Notification

<!-- CUSTOMIZE:
- If customer data is breached, who do you need to notify? This depends on your legal jurisdiction and customer contracts.
- Do you have customers in the EU (GDPR — 72-hour notification)? Canada (PIPEDA)? California (CCPA)? Other jurisdictions?
- Do your customer contracts or terms of service include breach notification commitments?
- Who in your organization is authorized to make breach notification decisions?
- Do you have a lawyer or legal firm you would contact? Do they have experience with breach notification?
- Have you ever had to notify anyone of a breach? What happened?
-->

### Notification Requirements

| Jurisdiction / Requirement | Notification Deadline | Who to Notify | Responsible Person |
|---------------------------|----------------------|---------------|-------------------|
| [e.g., GDPR (EU customers)] | [72 hours] | [Supervisory authority + affected individuals] | [e.g., CEO] |
| [e.g., PIPEDA (Canadian customers)] | [As soon as feasible] | [Privacy Commissioner + affected individuals] | [e.g., CEO] |
| [e.g., Customer contracts] | [Per contract terms] | [Affected customers] | [e.g., CEO] |
| [Add applicable requirements] | | | |

### Notification Process

If a breach requiring notification is confirmed:

1. [Describe who makes the notification decision — e.g., "The CEO, in consultation with legal counsel."]
2. [Describe legal counsel contact — e.g., "Contact [law firm name] at [contact info]" or "Legal counsel for breach notification has not been pre-arranged — this is a known gap."]
3. [Describe notification method — e.g., "Email notification to affected individuals using a pre-drafted template."]
4. [Describe what information is included in the notification.]

### Pre-Drafted Communications

[Describe whether you have pre-drafted breach notification templates ready, or note "Breach notification templates need to be prepared."]

## 9. Review Schedule

<!-- CUSTOMIZE:
- How often will you review this policy? Annually is the SOC 2 minimum, but incident response should ideally be reviewed after every significant incident.
- Do you conduct tabletop exercises (walk through a hypothetical incident to test the process)? How often?
-->

This policy is reviewed [annually / semi-annually] or when triggered by:

- After every Sev 1 or Sev 2 incident
- Changes to the team, systems, or infrastructure
- Changes to applicable laws or regulations
- After tabletop exercises reveal gaps

### Tabletop Exercises

[Organization Name] conducts tabletop incident response exercises [quarterly / semi-annually / annually / "we have not yet conducted one — the first is planned for [date]"]. These exercises simulate realistic incident scenarios to test and improve our response procedures.

The next scheduled review is [date].

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
