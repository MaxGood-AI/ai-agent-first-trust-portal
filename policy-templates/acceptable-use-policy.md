# Acceptable Use Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security
**SOC 2 References:** CC1.4, CC6.8
**Version:** 1.0 — Draft
**Last Review:** [Date]

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- Does this policy apply to all employees, contractors, interns, and temporary workers — or only specific groups?
- Do you provide company-owned devices, or do people use their personal devices for work (BYOD)?
- What company systems and resources does this policy cover? (e.g., laptops, email, Slack, cloud infrastructure, source code repositories, customer databases, internal tools)
- Is this policy acknowledged during onboarding? Do employees sign it? Is there an annual re-acknowledgment?
- How do you communicate this policy to new hires and existing staff?
-->

This policy defines the acceptable use of [Organization Name]'s information systems, devices, networks, and data. It applies to all employees, contractors, and third parties who access organizational resources.

The purpose is to protect the organization, its employees, and its customers from harm caused by misuse of technology resources — whether intentional or accidental.

## 2. Acceptable Use of Company Systems

<!-- CUSTOMIZE:
- Do you provide laptops/desktops to employees? What operating systems? Are they managed (MDM), or does each person set up their own?
- Are employees allowed to use company devices for personal activities? (e.g., personal email, personal browsing, streaming, gaming) If so, are there limits?
- Are employees allowed to install software on company devices? Do they need approval? Do they have admin/root access?
- Where should employees store work files? (e.g., Google Drive, company S3, local disk only as cache) Are there systems where work files should NOT be stored?
- Are there specific applications that are required on all company devices? (e.g., antivirus, screen lock, disk encryption, VPN)
- Do you use single sign-on (SSO)? Which systems are behind SSO and which aren't?
-->

### 2.1 General Principles

All users of [Organization Name]'s systems must:

- Use company resources primarily for business purposes
- Protect credentials and not share accounts or passwords
- Lock devices when leaving them unattended
- Report suspected security incidents immediately to [contact — e.g., security@example.com, CTO, Slack #security]
- Keep systems updated with the latest security patches

### 2.2 Permitted Use

- [Describe what is allowed — e.g., "Limited personal use is acceptable provided it does not interfere with work, consume excessive bandwidth, or violate any other provision of this policy."]

### 2.3 Prohibited Activities

The following are prohibited on company systems:

- [Tailor this list to your actual rules. Common prohibitions include:]
- Accessing, downloading, or distributing illegal content
- Attempting to bypass security controls or access systems without authorization
- Installing unauthorized software that could compromise security (e.g., torrent clients, unvetted browser extensions, cracked software)
- Storing customer data on personal devices or unapproved cloud services
- Sharing credentials, access tokens, or API keys through insecure channels (e.g., Slack messages, email, sticky notes)
- Using company resources for cryptocurrency mining or other resource-intensive personal activities
- Connecting unauthorized devices to the corporate network
- Disabling security software (antivirus, firewall, disk encryption)

### 2.4 Required Security Configuration

All devices used for work must have:

<!-- CUSTOMIZE:
- What security requirements do you actually enforce on devices? Be specific and honest — if you don't enforce disk encryption, don't list it here.
- Do you use an MDM solution to enforce these? Which one?
- What about phones/tablets used to access company email or Slack?
-->

- [ ] [e.g., Full-disk encryption enabled (FileVault on macOS, BitLocker on Windows)]
- [ ] [e.g., Screen lock after 5 minutes of inactivity]
- [ ] [e.g., Operating system auto-updates enabled]
- [ ] [e.g., Company-approved antivirus/endpoint protection installed]
- [ ] [e.g., Firewall enabled]
- [ ] [e.g., VPN installed and used when on untrusted networks]

## 3. Internet and Email Usage

<!-- CUSTOMIZE:
- Do you filter or block any categories of websites? (e.g., malware, adult content, gambling, social media)
- Are employees allowed to use personal email on company devices?
- Do you have rules about what can be sent via email vs. what must use a more secure channel?
- Can employees send customer data via email? Under what circumstances?
- Do you scan outbound emails for sensitive data (DLP)?
- Do you use email authentication (SPF, DKIM, DMARC) to prevent spoofing?
-->

### 3.1 Internet Usage

- Company internet access is provided for business purposes. [Describe your actual stance on personal browsing.]
- Users must not attempt to circumvent web filtering or proxy controls [if applicable]
- Downloads from untrusted sources are [prohibited/discouraged/allowed with caution]

### 3.2 Email Usage

- Company email must be used for all business communications. [Describe any exceptions.]
- Users must not [list actual prohibitions — e.g., open suspicious attachments, forward company email to personal accounts, send customer PII via unencrypted email]
- Email containing Confidential or Restricted data must [describe requirements — e.g., be encrypted, use a secure file-sharing link instead, be sent only to verified recipients]
- Phishing: [describe what employees should do when they receive a suspicious email — e.g., "Do not click links. Forward to security@example.com and delete."]

## 4. Personal Device Policy (BYOD)

<!-- CUSTOMIZE:
- Do you allow employees to use personal devices for work? Which activities? (e.g., checking email/Slack on personal phones, using personal laptops for development)
- If you allow BYOD, what security requirements do you impose? (e.g., screen lock, encryption, OS version, no jailbroken devices)
- Can employees access customer data from personal devices?
- Do you use an MDM solution for personal devices? Can you remote-wipe a personal device if it's lost?
- Do you provide a stipend for employees who use personal devices?
- What happens to work data on a personal device when an employee leaves? Can you enforce deletion?
- If you DON'T allow BYOD, say so clearly — that's a perfectly valid policy.
-->

### 4.1 BYOD Policy

[Choose one and customize:]

**Option A — BYOD Allowed with Restrictions:**

Personal devices may be used for the following work activities: [list specific activities — e.g., email, Slack, calendar only — NOT source code access or customer data access].

Personal devices used for work must meet these requirements:
- [ ] [e.g., Screen lock with PIN/biometric enabled]
- [ ] [e.g., Device encryption enabled]
- [ ] [e.g., Operating system within vendor support (no end-of-life OS versions)]
- [ ] [e.g., No jailbroken or rooted devices]
- [ ] [e.g., Company MDM profile installed (if applicable)]

**Option B — BYOD Not Permitted:**

All work must be performed on company-provided devices. Personal devices must not be used to access company systems, data, or communications. [Describe any exceptions, e.g., personal phone for 2FA only.]

### 4.2 Lost or Stolen Personal Devices

If a personal device used for work is lost or stolen:
1. Report to [contact] immediately — within [timeframe, e.g., 1 hour]
2. [Describe remote wipe capabilities and process]
3. [Describe password reset requirements for any accounts accessed from the device]

## 5. Remote Work Security

<!-- CUSTOMIZE:
- Is your team fully remote, hybrid, or in-office? Does this policy need to address all three?
- Do you require VPN use when working from home? When working from coffee shops or coworking spaces?
- Are there rules about working from public Wi-Fi? (e.g., airport, coffee shop)
- Do you have rules about screen privacy in public places? (e.g., privacy screens, not working on sensitive data in coffee shops)
- Do employees have dedicated home office setups, or do they work from shared spaces?
- Are there any geographic restrictions on where employees can work? (e.g., must work from Canada, cannot work from certain countries)
- Do you provide any security equipment for home offices? (e.g., hardware security keys, privacy screens, cable locks)
-->

### 5.1 Remote Work Requirements

All employees working remotely must:

- [e.g., Use a VPN when connecting to company resources from outside the corporate network]
- [e.g., Ensure their home Wi-Fi uses WPA2/WPA3 encryption with a strong password]
- [e.g., Not work on Confidential or Restricted data in public spaces where screens are visible to others]
- [e.g., Use a privacy screen when working in shared or public spaces]
- [e.g., Ensure physical security of devices — not left unattended in cars, hotel rooms, etc.]
- [e.g., Not use public/shared computers to access company systems]

### 5.2 Home Network Security

<!-- CUSTOMIZE:
- Do you provide guidance on home network security, or leave it up to employees?
- Do you require any specific home network configuration? (e.g., separate SSID for work devices, firmware updates on routers)
- Be realistic — most companies don't audit home networks, and that's OK. Just document what you expect.
-->

[Describe your actual expectations for home network security]

### 5.3 Geographic Restrictions

[Describe any restrictions on where employees may work — e.g., approved countries list, data residency considerations, tax/legal implications]

## 6. Monitoring and Enforcement

<!-- CUSTOMIZE:
- Do you monitor employee use of company systems? Be specific about what you monitor. (e.g., email content, web browsing, application usage, login times, file access)
- Do employees know they're being monitored? Is it stated in their employment agreement?
- Do you log access to sensitive systems? (e.g., production database access, customer data access, admin panel usage)
- Do you use any automated tools to detect policy violations? (e.g., DLP, SIEM, endpoint detection)
- Who reviews monitoring data? How often?
- Do you have an audit trail of who accessed what?
- Be transparent — employees have a right to know what's monitored. And auditors will check that your monitoring matches what you claim.
-->

### 6.1 Monitoring Scope

[Organization Name] monitors the following to protect organizational and customer data:

- [e.g., Access logs for all production systems and customer data stores]
- [e.g., Authentication events (successful and failed logins, MFA usage)]
- [e.g., Email and messaging for outbound data loss prevention (DLP) — content is not read by humans unless a DLP rule triggers]
- [e.g., Endpoint security events (malware detection, unauthorized software)]
- [e.g., Network traffic metadata (not content) for anomaly detection]

### 6.2 Employee Notification

[Describe how employees are informed about monitoring — e.g., "All employees are informed of monitoring practices during onboarding and acknowledge this policy in writing. The scope of monitoring is limited to company systems and does not extend to personal devices or personal accounts."]

### 6.3 Access to Monitoring Data

- Monitoring data is accessible to: [list roles — e.g., CTO, security team]
- Monitoring data is retained for: [timeframe]
- Monitoring data is reviewed: [frequency — e.g., real-time automated alerts, weekly manual review]

## 7. Violation Consequences

<!-- CUSTOMIZE:
- What actually happens when someone violates this policy? Walk through a realistic scenario.
- Do you have a progressive discipline process? (e.g., verbal warning, written warning, suspension, termination)
- Are some violations treated more seriously than others? What's an immediate termination offense vs. a coaching conversation?
- Who decides on consequences? HR? The employee's manager? The CTO?
- Do you document violations? Where?
- Have you ever enforced consequences for a policy violation? What happened?
- For contractors, what are the consequences? (Contract termination? Reduced access?)
-->

### 7.1 Violation Severity and Response

| Severity | Examples | Typical Response |
|----------|----------|-----------------|
| Minor | [e.g., Forgetting to lock screen, minor personal use excess] | [e.g., Verbal reminder and coaching] |
| Moderate | [e.g., Installing unauthorized software, sharing credentials via insecure channel, using personal cloud storage for work files] | [e.g., Written warning, mandatory security training, access review] |
| Serious | [e.g., Accessing systems without authorization, negligent handling of customer data, repeated moderate violations] | [e.g., Formal disciplinary action, access restrictions, performance improvement plan] |
| Critical | [e.g., Intentional data theft, malicious system access, sharing customer data externally without authorization] | [e.g., Immediate access revocation, investigation, potential termination and legal action] |

### 7.2 Investigation Process

1. Potential violation reported to or detected by [role]
2. Initial assessment by [role] to determine severity
3. Investigation conducted by [role/team], including [describe — e.g., log review, interviews]
4. Findings documented and shared with [roles — e.g., HR, employee's manager]
5. Consequences determined by [role] based on severity, intent, and history
6. Employee notified and given opportunity to respond
7. Decision implemented and documented

### 7.3 Contractors and Third Parties

Policy violations by contractors or third parties may result in:
- Immediate access revocation
- Contract termination
- Notification to the contracting organization
- Legal action if warranted

## 8. Review Schedule

<!-- CUSTOMIZE:
- How often will you review this policy? Technology and work patterns change — annual review is recommended.
- Who owns this policy? HR? IT? Security? A combination?
- Do you require annual employee re-acknowledgment of this policy?
-->

- This policy is reviewed [frequency — e.g., annually] by [role/team responsible]
- All employees must acknowledge this policy [frequency — e.g., at onboarding and annually]
- Next scheduled review: [date]
- Unscheduled reviews are triggered by:
  - Security incidents caused by policy violations
  - Significant changes to work practices (e.g., shift to remote work)
  - Changes to technology infrastructure
  - Regulatory changes affecting employee monitoring or privacy

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
