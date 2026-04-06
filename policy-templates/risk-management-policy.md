# Risk Management Policy

> **This is a template.** An AI agent will customize this policy based on your organization's actual practices. Every section marked with CUSTOMIZE must be filled in to reflect what you really do — not what you think you should do. SOC 2 auditors check whether you follow your own policies, so writing aspirational policies you don't follow is worse than having no policy.

**Category:** Security  
**SOC 2 References:** CC3.1, CC3.2, CC3.3, CC3.4, CC4.1, CC4.2  
**Version:** 1.0 — Draft  
**Last Review:** [Date]  

## 1. Purpose and Scope

<!-- CUSTOMIZE:
- What does "risk" mean at your organization? Are you thinking about it mostly as security risks, business continuity risks, compliance risks, or all of the above?
- Who is this policy for? Just leadership, or does every employee need to understand and participate in risk management?
- Does this cover risks across the whole company, or only technology/security risks?
- Are there risks managed by other policies (e.g., financial risks managed by your accountant) that are explicitly excluded?
-->

This policy defines how [Organization Name] identifies, assesses, treats, and monitors risks to the organization's operations, data, and customer commitments.

This policy applies to [all business and technology risks / technology and security risks only / describe actual scope] and is owned by [who -- CEO, CTO, a risk committee, etc.].

## 2. Risk Assessment Methodology

<!-- CUSTOMIZE:
- How do you actually identify risks today? Do you have a regular process, or does someone just think about it when something goes wrong?
- Who participates in risk identification? Just the CEO? The leadership team? The whole engineering team?
- How often do you actually assess risks? Quarterly? Annually? Only when prompted by an audit or incident?
- Do you use any specific framework or methodology (NIST, ISO 27005, FAIR), or is it informal? Be honest -- "informal but structured" is a valid answer.
- How do you rate the likelihood and impact of risks? Do you use a numeric scale (1-5), a simple High/Medium/Low, or gut feeling?
-->

### Assessment Process

Risk assessments are conducted [quarterly / semi-annually / annually / "when triggered by significant changes or incidents"] by [who -- CEO, leadership team, CTO, etc.].

The assessment process consists of:

1. **Risk Identification** -- [Describe how risks are identified -- e.g., "The leadership team brainstorms risks during a quarterly review meeting" or "Each team lead submits risks relevant to their area" or "We review incident reports, customer feedback, and industry threat intelligence."]
2. **Risk Analysis** -- Each risk is evaluated for likelihood and impact using the rating scale below.
3. **Risk Prioritization** -- Risks are ranked by their combined risk score to determine treatment priority.
4. **Documentation** -- Results are recorded in the risk register (see Section 3).

### Risk Rating Scale

#### Likelihood

| Rating | Definition |
|--------|-----------|
| **5 -- Almost Certain** | [Define in your terms -- e.g., "Expected to occur within the next year; has happened before"] |
| **4 -- Likely** | [e.g., "Probably will occur; similar events have occurred in our industry"] |
| **3 -- Possible** | [e.g., "Could occur; we can see plausible scenarios"] |
| **2 -- Unlikely** | [e.g., "Not expected, but not impossible"] |
| **1 -- Rare** | [e.g., "Only in exceptional circumstances"] |

#### Impact

<!-- CUSTOMIZE:
- What matters most to your business? Revenue loss? Customer trust? Regulatory fines? Operational disruption? The impact definitions should reflect what YOUR organization cares about.
- Consider: what would a Sev 1 incident cost you? Lost customers? Regulatory action? A bad day for the team? Use those concrete consequences to calibrate the scale.
-->

| Rating | Definition |
|--------|-----------|
| **5 -- Critical** | [Define in your terms -- e.g., "Business survival threatened; major data breach affecting all customers; regulatory action"] |
| **4 -- Major** | [e.g., "Significant financial loss (>$X); loss of key customers; extended outage (>24 hours)"] |
| **3 -- Moderate** | [e.g., "Moderate financial impact ($X-$Y); service degradation affecting many customers; negative press coverage"] |
| **2 -- Minor** | [e.g., "Small financial impact (<$X); brief disruption; affects a few customers"] |
| **1 -- Negligible** | [e.g., "Minimal impact; internal inconvenience only; no customer impact"] |

#### Risk Score

Risk Score = Likelihood x Impact

| Score Range | Risk Level | Action Required |
|-------------|-----------|-----------------|
| 15-25 | **Critical** | [e.g., "Immediate treatment required; escalate to CEO"] |
| 8-14 | **High** | [e.g., "Treatment plan required within 30 days"] |
| 4-7 | **Medium** | [e.g., "Treatment plan required within 90 days; monitor quarterly"] |
| 1-3 | **Low** | [e.g., "Accept and monitor; review during scheduled assessments"] |

## 3. Risk Register Management

<!-- CUSTOMIZE:
- Do you have a risk register today? Where does it live -- a spreadsheet, a tool, a document, or someone's mental model?
- If you don't have one yet, where will you create it? The trust portal has a built-in risk register -- will you use that?
- Who is responsible for keeping the risk register up to date?
- When was the last time someone actually looked at the risk register? If never, be honest.
- Who can add risks to the register? Anyone, or only certain people?
-->

### Risk Register Location

The risk register is maintained in [describe -- e.g., "the trust portal's risk management module" or "a spreadsheet in Google Drive at [location]" or "the risk register has not yet been created -- it will be established in [tool] by [date]"].

### Risk Register Contents

Each risk entry includes:

| Field | Description |
|-------|-------------|
| Risk ID | Unique identifier |
| Risk Description | Clear description of what could go wrong |
| Risk Category | [e.g., Security, Operational, Compliance, Third-party] |
| Likelihood | Rating 1-5 |
| Impact | Rating 1-5 |
| Risk Score | Likelihood x Impact |
| Risk Owner | Person responsible for managing this risk |
| Treatment | Accept, Mitigate, Transfer, or Avoid |
| Treatment Plan | Specific actions being taken |
| Status | Open, In Treatment, Accepted, Closed |
| Last Reviewed | Date of last review |

### Maintaining the Register

- New risks can be submitted by [anyone / team leads / leadership only] via [describe method -- e.g., "adding a row to the spreadsheet" or "submitting through the trust portal" or "raising it at the quarterly risk review meeting"].
- The risk register is reviewed and updated [quarterly / semi-annually / annually] by [who].
- Risks are never deleted -- closed or accepted risks remain in the register for audit trail purposes.

## 4. Risk Treatment

<!-- CUSTOMIZE:
- When you identify a risk, how do you decide what to do about it? Is there a formal decision process, or does the CEO/CTO just decide?
- What's your risk appetite? Are you conservative (fix everything) or pragmatic (accept some risk if the cost of fixing is disproportionate)?
- Do you have a budget for risk treatment, or are risk fixes prioritized alongside regular development work?
- Can you give an example of a risk you've accepted and why? (e.g., "We accept the risk of a single region outage because multi-region isn't worth the cost for our current customer base.")
- Can you give an example of a risk you've mitigated? (e.g., "We added MFA to reduce the risk of account takeover.")
-->

### Treatment Options

For each identified risk, one of the following treatment strategies is selected:

| Strategy | When Used | Example |
|----------|----------|---------|
| **Mitigate** | Reduce likelihood or impact through controls | [e.g., "Implement MFA to reduce unauthorized access risk"] |
| **Accept** | Risk is within appetite; cost of treatment exceeds benefit | [e.g., "Accept single-region deployment risk given current customer base"] |
| **Transfer** | Shift risk to a third party | [e.g., "Purchase cyber insurance" or "Use a managed service provider"] |
| **Avoid** | Eliminate the risk by removing the activity | [e.g., "Stop storing sensitive data we don't need"] |

### Risk Appetite

<!-- CUSTOMIZE:
- How much risk are you willing to accept? This is a business judgment, not a technical one.
- Are there any categories of risk you will NEVER accept? (e.g., "We will never accept the risk of unencrypted customer data at rest.")
- Is there a financial threshold -- e.g., "We'll accept risks with potential impact under $X but always mitigate risks above $X"?
-->

[Organization Name]'s risk appetite is [describe -- e.g., "low for risks involving customer data and moderate for operational risks" or "pragmatic -- we prioritize risks by potential customer impact and available resources"].

Risks that are NEVER acceptable regardless of likelihood:
- [e.g., "Unencrypted customer data at rest or in transit"]
- [e.g., "No access controls on production systems"]
- [Add any absolute requirements for your business]

### Treatment Approval

Risk treatment decisions are approved by [who -- e.g., "the CEO for Critical and High risks; the CTO for Medium and Low risks"].

Risk acceptance decisions (choosing not to mitigate) require approval from [who -- e.g., "the CEO, documented in the risk register with justification"].

## 5. Third-Party Risk Assessment

<!-- CUSTOMIZE:
- What third-party services does your application depend on? Think about: cloud providers, SaaS tools, payment processors, email services, monitoring tools, etc.
- How do you evaluate a new vendor before using them? Do you check if they have SOC 2? Do you review their security documentation? Or do you just sign up and start using it?
- Do you maintain a list of all your vendors and what data they have access to?
- Do you have contracts or data processing agreements with your key vendors?
- How do you monitor vendor risk over time? Do you re-evaluate vendors periodically, or only when something changes?
- Have you ever stopped using a vendor due to security concerns?
-->

### Vendor Assessment Process

Before adopting a new third-party service that will [access customer data / be part of the production infrastructure / handle sensitive information], [Organization Name] [describe what actually happens -- e.g., "reviews the vendor's SOC 2 report and security documentation" or "evaluates the vendor's security posture informally based on their website and documentation" or "does not currently have a formal vendor assessment process -- one will be established by [date]"].

### Assessment Criteria

| Criterion | What We Check | Required For |
|-----------|--------------|-------------|
| SOC 2 or equivalent certification | [e.g., "Review the SOC 2 Type 2 report"] | [e.g., "Any vendor with access to customer data"] |
| Data processing agreement | [e.g., "Ensure DPA is signed"] | [e.g., "Any vendor processing personal data"] |
| Encryption practices | [e.g., "Confirm data encrypted at rest and in transit"] | [e.g., "All vendors"] |
| Access controls | [e.g., "Verify MFA and least privilege"] | [e.g., "Vendors with system access"] |
| Incident notification | [e.g., "Confirm incident notification timeline in contract"] | [e.g., "All vendors"] |

### Vendor Inventory

A current inventory of third-party vendors is maintained in [describe -- e.g., "the trust portal's vendor management module" or "a spreadsheet at [location]" or "the vendor inventory has not yet been formalized"].

The inventory includes:
- Vendor name and purpose
- What data they access or process
- Their security certifications
- Contract and DPA status
- Last assessment date

### Ongoing Vendor Monitoring

Existing vendors are re-assessed [annually / when their SOC 2 report is updated / when contract renewals occur / "not currently on a schedule -- this will be formalized"].

## 6. Risk Monitoring and Reporting

<!-- CUSTOMIZE:
- How do you keep track of whether risks are getting better or worse? Do you have metrics or dashboards, or is it based on judgment?
- Who receives risk reports? The CEO? The board? The whole team? Nobody?
- How often are risk reports generated? Monthly? Quarterly? Only when asked?
- What format are the reports -- a formal document, a section in a meeting agenda, a dashboard, or a verbal update?
- Are there specific risk indicators you track? (e.g., number of security vulnerabilities, patch age, failed login attempts, uptime percentage.)
-->

### Monitoring

Risks are monitored through:

- **Risk register reviews** -- Conducted [quarterly / semi-annually / annually] by [who].
- **Key risk indicators** -- [Describe any metrics you track -- e.g., "Vulnerability scan results, uptime metrics, access review completion rates" or "We do not currently track formal risk indicators -- this will be implemented."]
- **Incident correlation** -- [Describe how incidents inform risk assessments -- e.g., "Post-incident reviews update the risk register with new or changed risks."]

### Reporting

| Report | Audience | Frequency | Format |
|--------|----------|-----------|--------|
| Risk Register Summary | [e.g., CEO / Leadership] | [e.g., Quarterly] | [e.g., Dashboard in trust portal / agenda item in leadership meeting] |
| Critical Risk Alerts | [e.g., CEO] | [e.g., Immediately upon identification] | [e.g., Email / Slack] |
| Vendor Risk Summary | [e.g., CTO] | [e.g., Annually] | [e.g., Spreadsheet review] |

### Risk Trend Tracking

[Organization Name] tracks risk trends by [describe -- e.g., "comparing risk scores quarter over quarter in the risk register" or "reviewing whether the overall number of high/critical risks is increasing or decreasing" or "risk trends are not currently tracked -- this capability is planned"].

## 7. Review Schedule

<!-- CUSTOMIZE:
- How often will you realistically review this policy?
- Should this policy review coincide with your risk assessment cycle?
- What events would trigger an immediate review?
-->

This policy is reviewed [annually / semi-annually] or when triggered by:

- A significant security incident or near-miss
- Major changes to business operations, infrastructure, or regulatory environment
- Findings from internal or external audits
- Changes to the organization's risk appetite (e.g., entering a new market, handling new data types)

The next scheduled review is [date].

## Review History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial version |
