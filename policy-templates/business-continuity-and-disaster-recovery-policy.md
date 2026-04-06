# Business Continuity and Disaster Recovery Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Availability
**SOC 2 References:** A1.1, A1.2, A1.3
**Version:** 1.0 — Draft
**Last Review:** [Date]

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What services do you provide that customers depend on? Which ones have uptime commitments (SLAs)?
- If your entire system went down right now, what would the business impact be? Lost revenue per hour? Customer churn? Contractual penalties?
- Does this policy cover just your production systems, or also internal tools (email, Slack, payroll)?
- Do you have a team responsible for incident response, or does everyone pitch in ad hoc?
- Have you ever had a significant outage? What happened, and what did you learn?
-->

This policy establishes [Organization Name]'s approach to maintaining business operations during disruptions and recovering from disasters. It covers the identification of critical systems, backup procedures, recovery plans, and testing schedules.

The goal is to minimize downtime and data loss when things go wrong — whether from infrastructure failures, security incidents, natural disasters, or human error.

## 2. Business Impact Analysis

<!-- CUSTOMIZE:
- List every production system/service your customers use. For each one, ask: if it went down, how long before customers start complaining? How long before you start losing customers?
- What's your actual tolerance for data loss? If you had to restore from backup, losing the last hour of data — would that be acceptable? The last 5 minutes? Zero data loss?
- Are there specific times when downtime would be especially damaging? (e.g., end of month for financial services, during a product launch)
- Do you have contractual SLAs with customers? What do they promise?
- Which internal systems are critical for your team to respond to an outage? (e.g., if Slack goes down during an AWS outage, can your team still coordinate?)
-->

### 2.1 Critical Systems

| System | Description | RTO | RPO | Impact if Unavailable |
|--------|-------------|-----|-----|----------------------|
| [e.g., Production API] | [e.g., Core backend serving all client requests] | [e.g., 1 hour] | [e.g., 5 minutes] | [e.g., All customers unable to use service] |
| [e.g., Primary Database] | [e.g., PostgreSQL on RDS storing all customer data] | [e.g., 30 minutes] | [e.g., 5 minutes] | [e.g., Complete service outage, potential data loss] |
| [e.g., Authentication Service] | [e.g., User login and session management] | [e.g., 1 hour] | [e.g., 0 — stateless] | [e.g., No new logins, existing sessions continue] |
| [e.g., Email/Communication] | [e.g., Internal coordination and customer support] | [e.g., 4 hours] | [e.g., N/A] | [e.g., Delayed customer support, slower incident response] |

**RTO** = Recovery Time Objective (maximum acceptable downtime)
**RPO** = Recovery Point Objective (maximum acceptable data loss, measured in time)

### 2.2 System Dependencies

<!-- CUSTOMIZE:
- What are the dependencies between your systems? If the database goes down, what else breaks?
- Do you depend on any single third-party service that, if it went down, would take your whole platform down? (e.g., AWS us-east-1, a specific API provider, a DNS provider)
- Are there any single points of failure in your architecture? (Be honest — most startups have them.)
-->

[Describe the dependency chain between critical systems and any single points of failure]

## 3. Backup Procedures

<!-- CUSTOMIZE:
- What is actually backed up today? Be specific — database, file storage, configuration, secrets, code.
- How often do backups run? Are they automated or manual?
- Where are backups stored? Same region as production? Different region? Different cloud provider?
- Have you ever restored from a backup? Did it work? How long did it take?
- Do you back up your infrastructure configuration (e.g., Terraform state, CloudFormation templates), or would you have to rebuild from memory?
- Are your backups encrypted? Who has access to them?
- Do you monitor whether backups are completing successfully, or would you only find out they're broken when you need them?
-->

### 3.1 Backup Schedule

| System | Backup Type | Frequency | Retention | Storage Location | Encryption |
|--------|------------|-----------|-----------|-----------------|------------|
| [e.g., PostgreSQL Database] | [e.g., Automated RDS snapshots] | [e.g., Daily + continuous WAL archiving] | [e.g., 30 days daily, 1 year monthly] | [e.g., AWS ca-central-1 with cross-region copy to us-east-1] | [e.g., AES-256 via KMS] |
| [e.g., File Storage (S3)] | [e.g., Cross-region replication] | [e.g., Real-time] | [e.g., Versioning enabled, 90-day lifecycle] | [e.g., Primary: ca-central-1, Replica: us-east-1] | [e.g., SSE-S3] |
| [e.g., Application Configuration] | [e.g., Git repository + parameter store] | [e.g., On every change] | [e.g., Full git history] | [e.g., CodeCommit + local clones] | [e.g., Encrypted at rest] |

### 3.2 Backup Verification

- Backup completion is monitored via: [describe — e.g., CloudWatch alarms, automated health checks, manual review]
- Backup integrity is verified by: [describe — e.g., automated restore tests, checksum validation, periodic manual restore]
- Backup restoration is tested: [frequency — e.g., quarterly, annually, never done it yet]

## 4. Disaster Recovery Plan

<!-- CUSTOMIZE:
- If your primary AWS region went completely offline, could you failover to another region? How long would it take?
- Do you have a documented, step-by-step runbook for recovery, or would your team have to figure it out in real-time?
- Who is authorized to declare a disaster and initiate the recovery plan? Is there a single point of contact, or a chain of command?
- What's your actual recovery process? Walk through what would happen if your production database was corrupted right now.
- Do you have a "break glass" procedure for emergency access when normal authentication is down?
- Could a single team member execute the recovery plan, or does it require multiple people? What if the person who knows the most is on vacation?
-->

### 4.1 Recovery Procedures

#### Scenario 1: Database Failure
1. [Step-by-step recovery procedure]
2. [Include who is responsible for each step]
3. [Include verification steps]

#### Scenario 2: Complete Region Outage
1. [Step-by-step recovery procedure]
2. [Include DNS/routing changes needed]
3. [Include data synchronization steps]

#### Scenario 3: Security Incident / Ransomware
1. [Step-by-step recovery procedure]
2. [Include isolation steps]
3. [Include clean restore procedure]

#### Scenario 4: Accidental Data Deletion or Corruption
1. [Step-by-step recovery procedure]
2. [Include point-in-time recovery steps]
3. [Include data validation steps]

### 4.2 Recovery Team

| Role | Primary | Backup | Contact Method |
|------|---------|--------|----------------|
| Incident Commander | [Name] | [Name] | [Phone/Slack/etc.] |
| Technical Lead | [Name] | [Name] | [Phone/Slack/etc.] |
| Communications Lead | [Name] | [Name] | [Phone/Slack/etc.] |
| Executive Sponsor | [Name] | [Name] | [Phone/Slack/etc.] |

## 5. High Availability Architecture

<!-- CUSTOMIZE:
- Do you run multiple instances of your application behind a load balancer, or is it a single server?
- Is your database configured for high availability? (e.g., RDS Multi-AZ, read replicas, clustering)
- Do you use auto-scaling? What triggers it?
- Are there any components that are NOT highly available? (e.g., a single Redis instance, a cron job server, a batch processing queue)
- Do you use multiple availability zones? Multiple regions?
- What happens when you deploy a new version — is there downtime? How do you handle rolling deployments?
-->

[Describe your actual high availability architecture. Include what IS and what IS NOT redundant. Be specific about which components have automatic failover and which require manual intervention.]

## 6. DR Testing Schedule

<!-- CUSTOMIZE:
- Have you ever tested your disaster recovery plan? When was the last time?
- What kind of test was it? (Tabletop discussion, partial failover, full failover?)
- What did you learn from the test? Did anything fail?
- How often can you realistically commit to testing? Consider the disruption to your team and customers.
- Do you test backup restoration separately from full DR tests?
-->

| Test Type | Frequency | Last Performed | Next Scheduled | Scope |
|-----------|-----------|----------------|----------------|-------|
| Backup Restoration Test | [e.g., Quarterly] | [Date or "Never"] | [Date] | [e.g., Restore database snapshot to test environment and verify data integrity] |
| Tabletop Exercise | [e.g., Semi-annually] | [Date or "Never"] | [Date] | [e.g., Walk through region-outage scenario with recovery team] |
| Partial Failover Test | [e.g., Annually] | [Date or "Never"] | [Date] | [e.g., Failover database to standby, verify application continues operating] |
| Full DR Test | [e.g., Annually] | [Date or "Never"] | [Date] | [e.g., Complete recovery from backup in alternate region] |

## 7. Communication Plan

<!-- CUSTOMIZE:
- When your service goes down, how do you currently notify customers? Do you have a status page? Do you email them? Post on social media?
- How quickly do you typically communicate about an outage? Is there a target time (e.g., within 15 minutes of detection)?
- Who decides what to communicate and when? Is there an approval process, or does the on-call person just post?
- Do you have pre-written templates for outage communications, or do you draft them from scratch each time?
- How do you communicate internally during an incident? What if your primary communication tool (e.g., Slack) is also down?
- Do you have contractual obligations to notify customers within a specific timeframe?
-->

### 7.1 Internal Communication

- Primary channel: [e.g., Slack #incidents channel]
- Backup channel: [e.g., Phone tree, SMS group, personal email]
- Escalation path: [describe who gets notified and when]

### 7.2 External Communication

- Status page: [URL or "not yet implemented"]
- Customer notification method: [e.g., email, in-app banner, status page]
- Notification timeline: [e.g., initial acknowledgment within 15 minutes, updates every 30 minutes]
- Post-incident report: [describe — e.g., published within 48 hours for major incidents]

### 7.3 Communication Templates

[Include or reference pre-written templates for common scenarios: investigating, identified, mitigated, resolved]

## 8. Review Schedule

<!-- CUSTOMIZE:
- How often will you realistically review and update this policy?
- Who owns this policy? A specific person, or a team?
- What events should trigger an immediate review? (e.g., after every real incident, after infrastructure changes, after DR tests reveal gaps)
-->

- This policy is reviewed [frequency — e.g., annually, semi-annually] by [role/team responsible]
- Next scheduled review: [date]
- Unscheduled reviews are triggered by:
  - Any actual disaster or significant outage
  - DR test failures or findings
  - Major infrastructure changes
  - Changes to customer SLAs or contractual obligations

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
