# Reflections: Building an AI Agent for Identity Security

## 1. Entra ID Object Model Nuances
* **App Registrations vs. Service Principals:** Initial audit runs missed ownership findings because `David Martinez` was assigned as owner on the tenant instance (`/servicePrincipals`), not the global registration (`/applications`).
* **Directory Roles vs. API Scopes:** Permissions were assigned via direct Directory Roles (`Privileged Authentication Administrator`) rather than Graph API delegated/application permissions, requiring multi-endpoint correlation.

## 2. LLM Context Optimization
* **Data Pre-processing:** Passing raw Graph API JSON payloads with hundreds of lines of OData metadata resulted in context bloat, slow execution times, and output hallucination.
* **Filtering Logic:** Sanitizing JSON output in Python to lightweight, 10-line dictionaries eliminated text corruption and vastly improved `gpt-4o` decision accuracy.

## 3. Tool Calling Precision
* Designing explicit function definitions and system instructions allowed the model to deterministically select the right endpoints without guessing or running unnecessary calls.
