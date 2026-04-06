# Vendor Management Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security
**SOC 2 References:** CC9.1, CC9.2
**Version:** 1.0 — Draft
**Last Review:** [Date]

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- How many third-party vendors/SaaS tools does your organization currently use? Do you have an inventory, or would you need to figure it out?
- Who currently decides whether to adopt a new tool or vendor? Is it one person, or can anyone sign up for a SaaS product?
- Have you ever had a security incident caused by or involving a vendor?
- Does this policy apply to all vendors, or only those that handle customer data or have access to your systems?
- Do you use any open-source software or self-hosted tools? Are those considered "vendors" for purposes of this policy?
-->

This policy defines how [Organization Name] evaluates, selects, monitors, and manages third-party vendors and service providers. It applies to all vendors that process, store, or have access to organizational or customer data, or that provide services critical to business operations.

The purpose is to ensure that third-party relationships do not introduce unacceptable risk to the organization or its customers.

## 2. Vendor Selection and Onboarding

<!-- CUSTOMIZE:
- When you choose a new SaaS tool, what do you check before signing up? Do you review their SOC 2 report? Do you require specific contract clauses?
- Who approves new vendor relationships? Is there a formal approval process, or does someone just sign up with a credit card?
- Do you have a vendor questionnaire or checklist? What does it cover?
- Is there a dollar threshold below which you skip the formal process? (e.g., "We don't review free tools" or "Anything under $500/year doesn't need approval")
- How long does your vendor evaluation process typically take? Days? Weeks? Or is it instantaneous?
- Do you distinguish between vendors that access customer data and those that don't?
-->

### 2.1 Vendor Evaluation Criteria

Before engaging a new vendor, the following must be assessed:

- [ ] **Security posture**: [describe what you check — e.g., SOC 2 Type 2 report, ISO 27001 certification, security questionnaire, penetration test results]
- [ ] **Data handling**: [describe — e.g., what data will they access, where will it be stored, is it encrypted]
- [ ] **Compliance**: [describe — e.g., regulatory compliance relevant to your industry, data residency requirements]
- [ ] **Business viability**: [describe — e.g., company size, financial stability, how long they've been operating]
- [ ] **Contractual terms**: [describe — e.g., data processing agreement, SLA, liability clauses, breach notification requirements]

### 2.2 Approval Process

| Vendor Risk Level | Approval Required From | Documentation Required |
|-------------------|----------------------|----------------------|
| Critical (accesses customer data, core infrastructure) | [e.g., CEO + CTO] | [e.g., Full security review, DPA, SOC 2 report review] |
| High (accesses internal data or systems) | [e.g., CTO] | [e.g., Security questionnaire, contract review] |
| Medium (business tools, no data access) | [e.g., Team lead] | [e.g., Basic evaluation checklist] |
| Low (free tools, no sensitive data) | [e.g., Any employee] | [e.g., None required] |

### 2.3 Onboarding Checklist

- [ ] Security review completed and documented
- [ ] Contract/terms of service reviewed and signed
- [ ] Data processing agreement (DPA) executed if applicable
- [ ] Vendor added to vendor inventory
- [ ] Access provisioned with least privilege
- [ ] Integration points documented
- [ ] Backup/exit plan documented

## 3. Vendor Risk Assessment

<!-- CUSTOMIZE:
- Do you currently assess vendor risk? If so, how? If not, what would a realistic starting point look like?
- What factors matter most to you when assessing vendor risk? Data access? System access? Business criticality? Revenue dependency?
- How do you find out if a vendor has had a security breach? Do you monitor vendor security news, or do you rely on them to tell you?
- Do you re-assess vendor risk periodically, or only when something goes wrong?
- Have you ever dropped a vendor because of security concerns?
-->

### 3.1 Risk Classification Criteria

| Factor | Low Risk | Medium Risk | High Risk | Critical Risk |
|--------|----------|-------------|-----------|---------------|
| Data Access | No org data | Internal data only | Customer metadata | Customer PII/content |
| System Access | None | Read-only internal | Write access to internal systems | Production infrastructure |
| Business Impact | Easily replaceable | Moderate switching cost | Significant switching cost | Service cannot operate without |
| Compliance | No regulatory scope | Indirect compliance impact | Direct compliance impact | Audit-critical |

### 3.2 Risk Assessment Frequency

| Risk Level | Assessment Frequency | Review Includes |
|------------|---------------------|-----------------|
| Critical | [e.g., Annually] | [e.g., SOC 2 report review, contract review, security assessment] |
| High | [e.g., Annually] | [e.g., SOC 2 or security questionnaire, contract review] |
| Medium | [e.g., Every 2 years] | [e.g., Terms of service review, access review] |
| Low | [e.g., At renewal] | [e.g., Verify still in use, basic review] |

## 4. Contract Requirements

<!-- CUSTOMIZE:
- Do your vendor contracts currently include security requirements? Which ones?
- Do you require a Data Processing Agreement (DPA) from vendors that handle customer data?
- Do your contracts include breach notification timelines? What's the required timeframe?
- Do you have termination clauses that allow you to exit if a vendor's security posture changes?
- Do you require vendors to carry cyber insurance?
- Who reviews contracts — legal counsel, or does the person signing up just accept the terms of service?
-->

All vendor contracts for Critical and High risk vendors must include:

- [ ] **Data protection clauses**: [describe specifics — e.g., encryption requirements, data residency, deletion upon termination]
- [ ] **Breach notification**: vendor must notify [Organization Name] within [timeframe, e.g., 72 hours] of discovering a breach affecting our data
- [ ] **Audit rights**: [describe — e.g., right to request SOC 2 report, right to audit, right to security questionnaire]
- [ ] **Sub-processor disclosure**: vendor must disclose and get approval for sub-processors that handle our data
- [ ] **Termination and data return**: [describe — e.g., data export within 30 days, certified deletion within 90 days]
- [ ] **SLA commitments**: [describe — e.g., uptime guarantees, support response times]
- [ ] **Insurance requirements**: [describe if applicable]

## 5. Ongoing Monitoring

<!-- CUSTOMIZE:
- How do you currently monitor whether your vendors are meeting their commitments? Do you check, or do you just trust them?
- Do you track vendor uptime or incidents? How?
- Do you review vendor SOC 2 reports when they're updated, or did you check once and never again?
- Do you monitor security news for your vendors? (e.g., would you know within a day if your email provider was breached?)
- Do you review vendor access logs? Can you tell who at the vendor accessed your data?
- Do you track vendor spending? Could a rogue employee sign up for expensive services without anyone noticing?
-->

### 5.1 Continuous Monitoring Activities

| Activity | Frequency | Responsible Party | Documentation |
|----------|-----------|-------------------|---------------|
| SOC 2/security report review | [e.g., Annually upon release] | [Role] | [e.g., Noted in vendor inventory] |
| Uptime/SLA tracking | [e.g., Monthly] | [Role] | [e.g., Automated monitoring] |
| Access review | [e.g., Quarterly] | [Role] | [e.g., Access audit log] |
| Security news monitoring | [e.g., Ongoing] | [Role] | [e.g., RSS feeds, security mailing lists] |
| Contract compliance review | [e.g., Annually] | [Role] | [e.g., Contract review notes] |

### 5.2 Vendor Incident Response

When a vendor reports a security incident or breach:

1. [Describe your actual response process — e.g., who gets notified, how you assess impact]
2. [Describe how you determine if your data was affected]
3. [Describe communication to your own customers if applicable]
4. [Describe documentation and follow-up requirements]

## 6. Sub-processor Management

<!-- CUSTOMIZE:
- Do you know which sub-processors your critical vendors use? For example, do you know where your SaaS vendors host their infrastructure?
- Do your contracts require vendors to notify you when they add a new sub-processor?
- Have you ever objected to a vendor's sub-processor? What happened?
- Do you pass through sub-processor notification requirements to your own customers?
-->

### 6.1 Sub-processor Requirements

- Critical and High risk vendors must maintain a current list of sub-processors that handle [Organization Name]'s data
- Vendors must notify [Organization Name] [timeframe, e.g., 30 days] before adding a new sub-processor
- [Organization Name] reserves the right to [describe — e.g., object to new sub-processors, terminate if objection is not resolved]

### 6.2 Sub-processor Inventory

[Maintain or reference a sub-processor inventory for critical vendors, including: vendor name, sub-processor name, service provided, data accessed, location]

## 7. Vendor Offboarding

<!-- CUSTOMIZE:
- When you stop using a vendor, what do you actually do? Do you have a checklist, or does someone just cancel the subscription?
- Do you revoke all access and API keys when you offboard a vendor? Who is responsible for this?
- Do you request confirmation that the vendor has deleted your data? Do you follow up?
- Have you ever had a situation where a deactivated vendor still had access to your systems?
- How do you handle vendors that go out of business?
-->

### 7.1 Offboarding Checklist

When ending a vendor relationship:

- [ ] All access credentials and API keys revoked
- [ ] SSO/SAML integration removed
- [ ] Data export completed and verified
- [ ] Vendor confirms deletion of all [Organization Name] data in writing
- [ ] Vendor removed from vendor inventory
- [ ] Integration points decommissioned
- [ ] DNS/firewall rules updated if applicable
- [ ] Employees notified of vendor change
- [ ] Replacement vendor (if any) fully operational before cutover

### 7.2 Data Retrieval and Deletion

- Request data export in [format, e.g., standard format, API export] within [timeframe] of termination notice
- Request written confirmation of data deletion within [timeframe] of contract end
- Verify deletion through [method — e.g., requesting deletion certificate, attempting API access]

## 8. Review Schedule

<!-- CUSTOMIZE:
- How often will you review the full vendor inventory? Is this realistic given your team size?
- Who owns vendor management? Is it a dedicated role, or part of someone's other responsibilities?
- What triggers an immediate vendor review outside the regular schedule?
-->

- Vendor inventory is reviewed [frequency — e.g., quarterly, semi-annually] by [role/team responsible]
- This policy is reviewed [frequency — e.g., annually] by [role/team responsible]
- Next scheduled review: [date]
- Unscheduled reviews are triggered by:
  - Vendor security incidents or breaches
  - Significant changes to vendor services or terms
  - Changes to organizational data handling requirements
  - Regulatory changes affecting vendor management

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
