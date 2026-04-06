# Data Classification and Handling Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Confidentiality
**SOC 2 References:** C1.1, C1.2
**Version:** 1.0 — Draft
**Last Review:** [Date]

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What types of data does your organization handle? (e.g., customer PII, financial records, health data, source code, internal communications)
- Does this policy apply to all employees, contractors, and third parties — or only certain teams?
- Are there specific regulatory requirements you must meet beyond SOC 2? (e.g., GDPR, HIPAA, PCI-DSS, PIPEDA)
- Do you have data that lives in systems you don't directly control (e.g., SaaS tools, customer-managed environments)?
-->

This policy defines how [Organization Name] classifies, handles, stores, and transmits data based on its sensitivity level. It applies to all employees, contractors, and third-party service providers who access organizational or customer data.

The purpose is to ensure that data receives the appropriate level of protection throughout its lifecycle — from creation through disposal — proportionate to the harm that would result from its unauthorized disclosure, modification, or loss.

## 2. Data Classification Levels

<!-- CUSTOMIZE:
- Do you currently label or tag your data by sensitivity? If not, how do people know what's sensitive?
- What's the most sensitive data you handle? What would happen if it leaked?
- Do you have data that's intentionally public (marketing content, docs, open-source code)?
- Is there data that only specific individuals should ever see (e.g., payroll, legal matters, security credentials)?
- How do you distinguish between "internal but not secret" and "truly confidential"?
-->

### 2.1 Public

Data intentionally made available to the general public. Unauthorized disclosure causes no harm.

**Examples:** [Provide real examples from your organization — e.g., marketing materials, published documentation, public-facing website content, open-source code]

### 2.2 Internal

Data intended for general internal use. Unauthorized disclosure would cause minor inconvenience but no significant harm.

**Examples:** [Provide real examples — e.g., internal meeting notes, non-sensitive project documentation, general company announcements, internal wiki pages]

### 2.3 Confidential

Data that could cause significant harm to the organization or its customers if disclosed. Access is restricted to authorized personnel with a business need.

**Examples:** [Provide real examples — e.g., customer data, employee PII, financial reports, unreleased product plans, source code, API keys, internal security assessments]

### 2.4 Restricted

The most sensitive data. Unauthorized disclosure could cause severe financial, legal, or reputational damage. Access is limited to named individuals.

**Examples:** [Provide real examples — e.g., encryption keys, root credentials, customer payment data, legal hold materials, security incident details, board-level financial data]

## 3. Handling Requirements by Classification Level

<!-- CUSTOMIZE:
- Where does each type of data actually live today? (e.g., AWS S3, Google Drive, local laptops, Slack messages, email)
- When people share confidential data internally, how do they do it? (e.g., Slack DM, shared drive, email attachment, password manager)
- Do you have any rules about printing sensitive data or displaying it on screens in shared spaces?
- Can employees download customer data to their local machines? Do they?
- Do you have different rules for production data vs. development/test data?
-->

| Requirement | Public | Internal | Confidential | Restricted |
|-------------|--------|----------|--------------|------------|
| Storage | Any | Approved systems | Encrypted, access-controlled | Encrypted, named-access only |
| Transmission | Any | Internal channels | Encrypted in transit | Encrypted, verified recipient |
| Access Control | None | Authentication required | Role-based, need-to-know | Named individuals, MFA required |
| Sharing | Unrestricted | Internal only | Approved recipients, NDA if external | CEO/CTO approval required |
| Labeling | None | Optional | Required | Required |
| Disposal | Standard delete | Standard delete | Secure delete, verified | Secure delete, audited, verified |

## 4. Encryption Standards

<!-- CUSTOMIZE:
- What cloud provider(s) do you use? Do they encrypt data at rest by default, or did you configure it?
- Do you use full-disk encryption on employee laptops? Is it enforced or optional?
- What TLS version do your services use? Do you know, or do you rely on cloud defaults?
- Do you manage your own encryption keys, or does your cloud provider manage them? (e.g., AWS KMS, customer-managed keys)
- Are there any systems where data is NOT encrypted at rest? (Be honest — auditors will find out.)
- Do you encrypt database backups? Where are they stored?
-->

### 4.1 Encryption at Rest

- All Confidential and Restricted data must be encrypted at rest using [specify algorithm, e.g., AES-256]
- Database encryption: [describe — e.g., AWS RDS encryption enabled, PostgreSQL TDE, application-level encryption]
- File storage encryption: [describe — e.g., S3 server-side encryption with KMS, EBS encryption]
- Endpoint encryption: [describe — e.g., FileVault on macOS, BitLocker on Windows, enforced via MDM]
- Backup encryption: [describe]

### 4.2 Encryption in Transit

- All external communications use TLS [specify version, e.g., 1.2 or higher]
- Internal service-to-service communication: [describe — e.g., TLS within VPC, mTLS, plaintext within private subnet]
- VPN requirements: [describe if applicable]

### 4.3 Key Management

- Encryption keys are managed via [describe — e.g., AWS KMS, HashiCorp Vault, manual rotation]
- Key rotation schedule: [describe]
- Key access is restricted to: [describe who]

## 5. Data Retention and Disposal

<!-- CUSTOMIZE:
- How long do you keep customer data after they cancel their account? Do you have a defined timeline, or does it just sit there?
- How long do you keep employee data after they leave?
- Do you have any legal or regulatory requirements that mandate specific retention periods?
- When you delete data, how do you do it? Do you just delete the database record, or do you also purge backups, logs, and caches?
- Do you have a process for responding to customer requests to delete their data? How long does it take?
- Are there any types of data you keep indefinitely? Why?
-->

| Data Type | Retention Period | Disposal Method | Legal Basis |
|-----------|-----------------|-----------------|-------------|
| [e.g., Customer account data] | [e.g., Duration of service + 30 days] | [e.g., Automated database purge + backup expiry] | [e.g., Contractual obligation] |
| [e.g., Application logs] | [e.g., 90 days] | [e.g., Automatic log rotation and deletion] | [e.g., Operational necessity] |
| [e.g., Financial records] | [e.g., 7 years] | [e.g., Secure shredding / verified deletion] | [e.g., Tax law requirement] |
| [e.g., Employee HR records] | [e.g., Duration of employment + 3 years] | [e.g., Secure deletion from HR system] | [e.g., Employment law] |

## 6. Customer Data Handling

<!-- CUSTOMIZE:
- What customer data do you collect? List it specifically — names, emails, usage data, uploaded content, payment info, IP addresses, etc.
- Where is customer data stored? Is it all in one place or spread across multiple systems?
- Can your employees access individual customer data? Who can, and how?
- Do you use customer data for anything beyond providing the service? (e.g., analytics, training ML models, marketing)
- Do you have customers in the EU or other jurisdictions with specific data protection laws?
- If a customer asks "where is my data and who has accessed it," can you answer that question today?
- Do you share customer data with any third parties? (e.g., analytics tools, payment processors, support tools)
-->

### 6.1 Customer Data Inventory

[List the specific types of customer data your organization collects, processes, and stores]

### 6.2 Data Isolation

[Describe how customer data is isolated — e.g., multi-tenant with logical separation, database-level isolation, separate encryption keys per customer]

### 6.3 Customer Data Access

- Customer data access is limited to: [describe who and under what circumstances]
- Access logging: [describe how access to customer data is logged]
- Customer-facing data export: [describe self-service export capabilities]
- Customer-facing data deletion: [describe self-service deletion capabilities]

### 6.4 Third-Party Data Sharing

[List any third parties that receive or can access customer data, and the purpose for each]

## 7. Review Schedule

<!-- CUSTOMIZE:
- How often do you realistically review policies? Be honest — if you've never reviewed a policy after writing it, say "annually" and commit to actually doing it.
- Who should be responsible for reviewing this policy? Is it one person or a group?
- What would trigger an unscheduled review? (e.g., a data breach, a new regulation, a major system change)
-->

- This policy is reviewed [frequency — e.g., annually, semi-annually] by [role/team responsible]
- Next scheduled review: [date]
- Unscheduled reviews are triggered by:
  - Security incidents involving data exposure
  - Changes to regulatory requirements
  - Significant changes to data processing systems or practices
  - Customer or auditor findings

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
