# Independent Code Review Prompt Template

This prompt is used by the main AI agent (e.g., Claude Code) to invoke an independent review agent (e.g., OpenAI Codex) as an automated step in the KanbanZone Card Workflow.

The main agent substitutes `{{ CARD_NUMBER }}`, `{{ BOARD_URL }}`, and `{{ REPO_LIST }}` before invoking the review agent.

---

## Prompt

```
Please analyze all the changes in {{ REPO_LIST }} related to card #{{ CARD_NUMBER }}, BUT DO NOT make any further changes yourself.

Your analysis should check:

1. **Functionality** — new functionality looks correct and complete relative to the approved plan on the card
2. **Refactoring** — any refactoring looks complete and correct; no dead code, no orphaned references
3. **Cross-repo consistency** — references between repos are consistent (API contracts, shared types, environment variables)
4. **Security** — no committed secrets, no hardcoded credentials, no OWASP top 10 vulnerabilities (injection, XSS, etc.), no unsafe input handling
5. **Unit tests** — complete unit tests exist covering happy path, edge cases, and malicious/adversarial input
6. **E2E tests** — any applicable end-to-end tests are created or updated, covering edge cases and malicious input
7. **Test execution** — all tests run successfully (run the test suites)
8. **Lint/style** — code passes all configured linters with zero warnings

This is a complete static and dynamic analysis of all current uncommitted changes.

Your report should be detailed and actionable with clear file:line references. Include a final **VERDICT: PASS** or **VERDICT: FAIL** with a summary of any blocking issues.

Emit this report by appending a `### Independent Code Review` section to card #{{ CARD_NUMBER }} on the KanbanZone board at {{ BOARD_URL }}.
```

---

## Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{{ CARD_NUMBER }}` | The KanbanZone card number being worked on | `461` |
| `{{ BOARD_URL }}` | The KanbanZone board URL | `https://kanbanzone.io/b/QJxJGohF` |
| `{{ REPO_LIST }}` | Repos with changes, or "all repos" | `./MyBackend and ./MyFrontend` |

## How the Main Agent Uses This

After the user accepts the completed work (step 6 of the card workflow), the main agent:

1. Reads this prompt template
2. Substitutes the placeholders with actual values
3. Invokes the review agent CLI (e.g., `codex --prompt "<composed prompt>"`)
4. Waits for the review agent to complete and append findings to the card
5. Reads the card to check the verdict
6. If **VERDICT: PASS** — proceeds to commit
7. If **VERDICT: FAIL** — presents the blocking issues to the user for resolution before retrying
