# Privacy and Data Protection Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Privacy
**SOC 2 References:** P1.1, P1.2, P2.1, P3.1, P3.2, P4.1, P5.1, P5.2, P6.1, P6.7, P7.1, P8.1
**Version:** 1.0 — Draft
**Last Review:** [Date]

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What privacy laws apply to your organization? (e.g., GDPR if you have EU users, CCPA/CPRA for California, PIPEDA for Canada, state-specific laws)
- Do you have a public privacy policy on your website? When was it last updated? Does it accurately describe what you actually do?
- Who in your organization is responsible for privacy? Is there a designated Data Protection Officer (DPO), or does someone handle it informally?
- Do you process personal data for anyone other than your direct customers? (e.g., your customers' end users, employees' dependents, job applicants)
- Have you ever received a data subject access request, deletion request, or privacy complaint? How did you handle it?
-->

This policy defines how [Organization Name] collects, processes, stores, and protects personal data. It applies to all personal data processed by the organization, whether belonging to customers, employees, prospective customers, or any other individuals.

This policy ensures compliance with applicable privacy regulations and establishes the practices necessary to protect individuals' privacy rights.

## 2. Personal Data Definition

<!-- CUSTOMIZE:
- What personal data do you actually collect? List everything — be thorough. Common categories: names, email addresses, phone numbers, IP addresses, device identifiers, usage/behavioral data, location data, payment information, employer/job title, social media handles, uploaded content that may contain PII.
- Do you collect any sensitive/special category data? (e.g., health information, racial/ethnic origin, political opinions, biometric data, sexual orientation, religious beliefs)
- Do you collect personal data about children (under 13/16 depending on jurisdiction)?
- Where does personal data enter your systems? (e.g., sign-up forms, API integrations, email, chat messages, uploaded documents, analytics tracking)
- Do you collect personal data indirectly — for example, through cookies, analytics, or third-party integrations?
-->

### 2.1 Categories of Personal Data Processed

| Category | Specific Data Elements | Source | Purpose |
|----------|----------------------|--------|---------|
| [e.g., Identity Data] | [e.g., Full name, email address, profile photo] | [e.g., User registration] | [e.g., Account creation and authentication] |
| [e.g., Usage Data] | [e.g., Feature usage, session duration, pages visited] | [e.g., Application analytics] | [e.g., Product improvement, support] |
| [e.g., Communication Data] | [e.g., Chat messages, email content] | [e.g., In-app messaging, email integration] | [e.g., Core service delivery] |
| [e.g., Technical Data] | [e.g., IP address, browser type, device ID] | [e.g., Automatic collection] | [e.g., Security, troubleshooting] |
| [e.g., Payment Data] | [e.g., Billing address, payment method (last 4 digits only)] | [e.g., Checkout flow] | [e.g., Payment processing] |

### 2.2 Sensitive Data

[Describe whether you collect any sensitive/special category data, and if so, what additional protections are applied]

## 3. Legal Basis for Processing

<!-- CUSTOMIZE:
- For each type of personal data you collect, why do you collect it? Can you tie it to a specific legal basis?
- Do you rely on consent for any data processing? If so, how do you collect consent? Can users withdraw it? How?
- Do you process any data based on "legitimate interest"? If so, have you documented what that interest is and balanced it against the individual's rights?
- Do you have contractual obligations that require you to process certain data?
- Do you process data for purposes beyond what the user signed up for? (e.g., using customer data for marketing, training ML models, selling to third parties)
-->

| Processing Activity | Legal Basis | Justification |
|---------------------|-------------|---------------|
| [e.g., Account creation and authentication] | [e.g., Contractual necessity] | [e.g., Required to provide the service the user signed up for] |
| [e.g., Product analytics] | [e.g., Legitimate interest] | [e.g., Understanding usage patterns to improve the product; balanced against minimal privacy impact of aggregated data] |
| [e.g., Marketing emails] | [e.g., Consent] | [e.g., Opt-in checkbox at registration; withdrawal via unsubscribe link] |
| [e.g., Security logging] | [e.g., Legitimate interest] | [e.g., Detecting and preventing unauthorized access; essential for security] |
| [e.g., Legal compliance] | [e.g., Legal obligation] | [e.g., Tax records retention, law enforcement requests] |

## 4. Data Subject Rights

<!-- CUSTOMIZE:
- If a customer emails you right now asking "what data do you have about me," could you answer? How long would it take? Who would handle it?
- If a customer asks you to delete all their data, can you do it? What systems would you need to touch? Are there any systems where you can't easily delete individual records (e.g., backups, logs, analytics)?
- Can customers export their data in a machine-readable format? Is this self-service or manual?
- Do you have a published process for data subject requests (e.g., a privacy email address, a form on your website)?
- What's your target response time for data subject requests? What's your actual response time?
- Have you ever denied a data subject request? On what grounds?
-->

[Organization Name] supports the following data subject rights:

### 4.1 Supported Rights

| Right | Description | How to Exercise | Response Time |
|-------|-------------|-----------------|---------------|
| Access | Know what personal data we hold | [e.g., Email privacy@example.com or self-service in account settings] | [e.g., 30 days] |
| Rectification | Correct inaccurate data | [e.g., Self-service in account settings, or email request] | [e.g., 7 days] |
| Erasure / Deletion | Request deletion of personal data | [e.g., Email privacy@example.com] | [e.g., 30 days to process, backups expire within 90 days] |
| Portability | Receive data in machine-readable format | [e.g., Self-service export, or email request] | [e.g., 30 days] |
| Restriction | Limit processing of personal data | [e.g., Email privacy@example.com] | [e.g., 7 days] |
| Objection | Object to processing based on legitimate interest | [e.g., Email privacy@example.com] | [e.g., 30 days] |
| Withdraw Consent | Withdraw previously given consent | [e.g., Unsubscribe link, account settings, or email request] | [e.g., Immediate for marketing; 7 days for other processing] |

### 4.2 Request Handling Process

1. Request received via [channel]
2. Identity verified by [method — e.g., confirming account email, requesting government ID for sensitive requests]
3. Request logged in [system]
4. Request fulfilled by [role] within [timeframe]
5. Confirmation sent to requestor
6. Request documented for compliance records

### 4.3 Limitations

[Describe any circumstances where you may not be able to fully comply with a request — e.g., legal retention requirements, data in backups, anonymized/aggregated data that can no longer be linked to an individual]

## 5. Privacy by Design

<!-- CUSTOMIZE:
- When you build new features, do you consider privacy implications before building? Is there a formal review, or is it informal?
- Do you practice data minimization — i.e., do you only collect what you actually need? Or do you collect "everything, just in case"?
- Do you have default privacy settings for new users? Are they privacy-protective (opt-in) or permissive (opt-out)?
- Do you anonymize or pseudonymize data where possible? In which systems?
- Do you have a process for reviewing whether you still need data you collected in the past?
- When you design database schemas or APIs, do you consider how you'll handle deletion requests?
-->

### 5.1 Privacy Principles in Development

[Organization Name] applies the following privacy principles when designing and building systems:

- **Data Minimization**: [describe your actual practice — e.g., "We only collect fields required for core functionality. New data collection requires justification and approval from [role]."]
- **Purpose Limitation**: [describe — e.g., "Data collected for one purpose is not repurposed without user consent."]
- **Storage Limitation**: [describe — e.g., "We define retention periods for all data categories and enforce automatic deletion."]
- **Privacy-Protective Defaults**: [describe — e.g., "New accounts default to minimal data sharing. Marketing communications are opt-in."]
- **Anonymization/Pseudonymization**: [describe where and how you apply these techniques]

### 5.2 Privacy Review in Development Process

[Describe how privacy is considered during feature development — e.g., privacy checklist in code review, mandatory review for features that process new categories of personal data, privacy section in design documents]

## 6. Cross-Border Data Transfers

<!-- CUSTOMIZE:
- Where are your servers located? Which cloud regions do you use?
- Do you have customers in the EU/EEA? If so, does their data stay within the EU, or is it transferred outside?
- Do you use any vendors or sub-processors that store or process data outside your primary jurisdiction?
- If you transfer data internationally, what legal mechanism do you rely on? (e.g., Standard Contractual Clauses, adequacy decisions, binding corporate rules, consent)
- Do you have employees or contractors in other countries who can access customer data?
-->

### 6.1 Data Residency

- Primary data storage location: [e.g., AWS ca-central-1 (Canada)]
- Backup data location: [e.g., AWS us-east-1 (United States)]
- CDN/edge locations: [describe if applicable]

### 6.2 International Transfers

| Data Type | Origin | Destination | Legal Mechanism | Safeguards |
|-----------|--------|-------------|-----------------|------------|
| [e.g., Customer data] | [e.g., EU] | [e.g., Canada] | [e.g., EU adequacy decision for Canada (PIPEDA)] | [e.g., Encryption in transit and at rest] |
| [e.g., Support data] | [e.g., Global] | [e.g., US-based support tool] | [e.g., Standard Contractual Clauses] | [e.g., DPA with vendor, access controls] |

## 7. Privacy Impact Assessments

<!-- CUSTOMIZE:
- Do you currently perform Privacy Impact Assessments (PIAs) or Data Protection Impact Assessments (DPIAs)? Have you ever done one?
- What would trigger a PIA in your organization? (e.g., new product launch, new vendor that handles PII, new data collection, entering a new market)
- Who would conduct a PIA? Do you have internal expertise, or would you need external help?
- Where would you document PIA results?
-->

### 7.1 When a PIA is Required

A Privacy Impact Assessment must be conducted before:

- [e.g., Launching a new product or feature that processes personal data in a new way]
- [e.g., Adopting a new vendor or sub-processor that will access personal data]
- [e.g., Entering a new geographic market with different privacy regulations]
- [e.g., Making significant changes to how existing personal data is processed]
- [e.g., Implementing new surveillance or monitoring technologies]

### 7.2 PIA Process

1. [Describe who initiates the PIA]
2. [Describe the assessment methodology]
3. [Describe how risks are identified and mitigated]
4. [Describe how results are documented and reviewed]
5. [Describe how findings are tracked to resolution]

## 8. Breach Notification

<!-- CUSTOMIZE:
- Do you have a process for detecting that a privacy breach has occurred? How would you find out — automated monitoring, user report, vendor notification?
- Who needs to be notified internally when a privacy breach is discovered? What's the chain of communication?
- Do you know the breach notification timelines for the jurisdictions where you operate? (e.g., GDPR requires 72 hours to the supervisory authority; many US states have their own timelines)
- Have you ever experienced a privacy breach? How did you handle notification?
- Do you have pre-written breach notification templates, or would you draft them from scratch?
- Do you have cyber insurance that covers breach notification costs?
-->

### 8.1 Breach Classification

| Severity | Criteria | Notification Required |
|----------|----------|----------------------|
| Critical | [e.g., Confirmed exposure of sensitive PII, large number of individuals affected] | [e.g., Regulatory authority within 72 hours, affected individuals without undue delay] |
| High | [e.g., Confirmed exposure of personal data, limited number affected] | [e.g., Regulatory authority within 72 hours, affected individuals assessed case-by-case] |
| Medium | [e.g., Potential exposure, no confirmation of unauthorized access] | [e.g., Internal investigation, regulatory notification assessed case-by-case] |
| Low | [e.g., Data exposed but encrypted/pseudonymized, minimal risk to individuals] | [e.g., Internal documentation, no external notification required] |

### 8.2 Notification Process

1. **Detection and Containment** (within [timeframe]):
   - Breach identified through [channels — e.g., automated monitoring, employee report, vendor notification]
   - Immediate containment steps taken by [role]
   - Incident Commander notified

2. **Assessment** (within [timeframe]):
   - Scope of breach determined: what data, how many individuals, what jurisdictions
   - Risk to affected individuals assessed
   - Legal obligations determined based on jurisdiction and data types

3. **Internal Notification** (within [timeframe]):
   - [List internal stakeholders who must be notified — e.g., CEO, legal counsel, privacy officer]

4. **Regulatory Notification** (within [timeframe, aligned with legal requirements]):
   - [List applicable authorities — e.g., Privacy Commissioner of Canada, EU supervisory authority, state attorneys general]
   - Notification includes: nature of breach, categories of data, approximate number of individuals, likely consequences, measures taken

5. **Individual Notification** (within [timeframe]):
   - Method: [e.g., email, registered mail for high severity]
   - Content: plain-language description of what happened, what data was affected, what we're doing about it, what they can do, contact information for questions

6. **Post-Breach Review** (within [timeframe]):
   - Root cause analysis completed
   - Remediation steps implemented
   - Policy and procedure updates as needed
   - Documentation retained for [retention period]

## 9. Review Schedule

<!-- CUSTOMIZE:
- How often will you review this policy? Privacy laws change frequently — annual review is the minimum.
- Who is responsible for tracking changes in privacy regulations?
- Do you have legal counsel who advises on privacy matters, or do you rely on internal knowledge?
-->

- This policy is reviewed [frequency — e.g., annually] by [role/team responsible]
- Privacy practices are audited [frequency] by [internal/external auditor]
- Next scheduled review: [date]
- Unscheduled reviews are triggered by:
  - Privacy breaches or incidents
  - Changes to applicable privacy regulations
  - New processing activities or significant changes to existing ones
  - Customer or regulatory complaints
  - Entry into new geographic markets

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
