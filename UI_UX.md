# UI_UX.md

## Universal User Experience, Interface, Accessibility, and Visual Quality Standard

**Scope:** Technology-, platform-, device-, and domain-neutral. Apply only the sections relevant to the actual deliverable and its users. This standard supports information systems (IS), internal and public-facing business applications, point-of-sale (POS) systems, inventory and order management, finance and accounting tools, enterprise resource planning (ERP), customer relationship management (CRM), administrative portals, operational and security tools, developer tools, dashboards, workflow systems, websites, web and mobile apps, desktop software, embedded systems, CLI/TUI experiences, games, documents, reports, presentations, design systems, and other product categories. This list is illustrative, not restrictive. APIs, libraries, backend services, infrastructure, and headless systems do not need an invented graphical interface; apply only relevant human-facing surfaces such as documentation, configuration, diagnostics, logs, command output, and operator workflows.

**Purpose:** Define a practical quality standard for understanding, evaluating, designing, improving, and validating real user experiences without inventing product capabilities or violating architecture, security, data integrity, or established contracts.

> **Governing principle:** Improve how people understand and use the product while preserving verified product truth, business rules, security, data integrity, and architecture.

---

## 1. Applicability and Authority

First identify the actual deliverable, users, tasks, supported environments, and interaction surfaces. Apply only relevant requirements. Mark irrelevant checks **Not applicable**, not **Failed** or **Missing**.

Use the project's current authoritative documentation and implementation to understand its purpose, constraints, architecture, design system, supported platforms, and conventions. Common sources may include `README.md`, `ARCHITECTURE.md` or equivalent architecture documentation, project-specific `UI_UX.md` guidance, product requirements, developer instructions, API contracts, and tests. Do not assume a fixed filename or that every document exists.

This file defines universal experience-quality principles. It does not replace project-specific architecture, requirements, security policies, or implementation instructions. If requirements conflict, identify the conflict and follow the applicable authority. Ask a concise question only when an unresolved material conflict prevents safe, correct work.

Technology and platform neutrality means:
- Do not mandate a particular language, framework, UI library, database, operating system, device, design style, or deployment model.
- Respect established project conventions and platform-specific accessibility and interaction expectations.
- Do not force graphical, touch, responsive-web, image-generation, or runtime-testing requirements onto deliverables that do not support them.
- Do not invent features, screens, controls, content, data, or workflows to satisfy a checklist.

## 2. Quality Goals

Where relevant to the product and its audience, the experience should be:

- **Understandable:** Purpose, terminology, status, and next steps are clear.
- **Usable:** Common tasks can be completed with reasonable effort and few avoidable mistakes.
- **Predictable:** Similar actions behave consistently and outcomes are communicated.
- **Accessible:** Supported users and input methods can access essential information and tasks.
- **Coherent:** Information hierarchy, interaction patterns, language, and visual style work together.
- **Trustworthy:** Displayed data, permissions, statuses, and success messages reflect verified system behavior.
- **Efficient:** Performance and workflow complexity are appropriate to the task.
- **Resilient:** Errors, empty results, interruptions, and recovery are handled deliberately.
- **Maintainable:** Improvements fit the architecture and reuse appropriate shared patterns.

Prioritize successful task completion over novelty or decoration. Avoid generic, prototype-like presentation; excessive cards, effects, or animation; redundant controls; inconsistent patterns; fabricated content; and visual polish that conceals functional defects.


## 2A. AUTONOMOUS PREMIUM DESIGN AND LAYOUT

When the deliverable includes a user-facing interface or experience, independently pursue a polished, premium, production-ready result without requiring pixel-level instructions from the user.

### Design decisions
- Infer the appropriate visual direction from verified product purpose, audience, workflow, brand assets, platform conventions, existing design tokens, and current implementation.
- Choose a cohesive layout, information hierarchy, typography, spacing scale, color palette, surfaces, borders, elevation, iconography, and component treatment that fit the actual product.
- Optimize for clarity, trust, efficient task completion, accessibility, and appropriate information density—not decoration alone.
- Make related screens feel like one product through consistent navigation, tokens, components, terminology, interaction patterns, and state feedback.
- Use the complexity and visual richness appropriate to the product. A premium result may be restrained, information-dense, editorial, technical, or visually expressive depending on context; do not force one style on every product.
- Prefer deliberate, high-quality layouts over generic template-like screens, arbitrary card grids, default-looking controls, inconsistent spacing, excessive whitespace, or unnecessary visual effects.
- Do not add unsupported features, fabricated data, decorative metrics, fake status indicators, or controls that do not perform real actions.

### Reference images and examples
Treat a user-provided screenshot, mockup, or design reference as a quality benchmark and source of visual direction—not an instruction to copy every element regardless of context. Extract relevant qualities such as hierarchy, composition, polish, density, color relationships, and interaction clarity. Adapt them to the actual product's purpose, supported workflows, brand, data, platform, and architecture.

### Autonomous execution
Do not stop after describing design recommendations when implementation is authorized and feasible. Identify the highest-impact design and usability issues, choose a justified solution, implement it using the existing architecture and reusable patterns, and validate the result. Make routine, reversible decisions autonomously; ask only when an essential product decision, material risk, or genuine blocker cannot be resolved from available evidence.

### Premium-quality gate
Before declaring a relevant UI/UX task complete, assess:
- Clear purpose and strong information hierarchy.
- Consistent typography, spacing, alignment, color, components, and visual language.
- Efficient real-world workflows and discoverable primary actions.
- Functional controls and truthful data/status presentation.
- Appropriate responsive behavior and accessibility for supported environments.
- Complete relevant loading, empty, error, success, disabled, and recovery states.
- No obvious clipping, overflow, awkward wrapping, visual inconsistency, dead controls, or placeholder-like presentation.
- Actual rendered before/after inspection where the environment supports it.

Aim for exceptional quality, but do not claim a 10/10 score or visual success without sufficient evidence. If rendering is unavailable, label the review as source-level and explicitly identify the visual behavior that remains unverified. Apply this gate only where a user-facing experience exists; do not invent a graphical interface for headless deliverables.

## 2B. ENTERPRISE-PREMIUM CRAFT AND DESIGN EXECUTION

This section strengthens the universal quality bar; it does not mandate a single aesthetic, layout, framework, or visual trend. Apply it only to relevant user-facing deliverables.

### Design with intent, not decoration

Infer the product's purpose, users, highest-value tasks, information density, environment, brand cues, and constraints from authoritative project evidence. Then make coherent design decisions without waiting for pixel-level instructions.

A premium result is not simply a dark theme, gradients, rounded cards, shadows, glass effects, or animation. It is a deliberate experience in which visual hierarchy, content, interaction, and implementation reinforce one another. Select a restrained or expressive style according to the product and users—not fashion.

### Composition and hierarchy
- Establish a clear page-level composition before polishing individual components: navigation, page identity, primary task, supporting information, and contextual actions.
- Give every region a reason to exist. Use grouping, spacing, alignment, typography, contrast, and scale to communicate relationships and importance.
- Make primary actions unmistakable and secondary actions quieter without hiding essential functionality.
- Balance information density with scanability. Dense operational interfaces should remain efficient; consumer or editorial experiences may need more breathing room.
- Design for real content lengths, localization, data variation, permission differences, and edge cases—not only ideal sample data.
- Avoid repetitive card grids, oversized headings, excessive whitespace, arbitrary dividers, decorative metrics, and competing visual focal points when they do not serve the task.

### Design-system coherence
- Define or reuse a coherent set of design tokens and patterns for color roles, typography, spacing, sizing, borders, elevation, focus, motion, and component states where the platform supports them.
- Use semantic color roles consistently: color must not be the sole carrier of meaning, and status colors must not be used decoratively.
- Prefer consistent shared components for repeated patterns. Correct a shared root cause centrally when safe instead of applying inconsistent per-screen patches.
- Keep icon style, stroke/weight, sizing, alignment, button hierarchy, field treatment, navigation, tables, overlays, and feedback patterns consistent.
- Introduce variation only when it communicates a real difference in hierarchy, purpose, or state.
- Avoid token proliferation, parallel design systems, arbitrary one-off values, and abstractions that make simple changes harder.

### Component and interaction craft
For each relevant component, evaluate its purpose, hierarchy, content fit, hit/focus area, affordance, accessibility, responsiveness, and behavior. Check applicable default, hover, focus, pressed, selected, disabled, loading, invalid, success, and destructive states. Do not create states that are irrelevant to the platform or component.

Every visible control must have a real, correctly authorized outcome. Its label, visual treatment, confirmation, and feedback must match the operation. Distinguish destructive and irreversible actions clearly; use confirmation only when proportionate to risk. Preserve user input and context when appropriate.

### Data-rich and operational experiences
For dashboards, administration tools, forms, tables, inventory systems, editors, and other information-dense products, optimize for comprehension and task throughput:
- Put the most decision-relevant information first.
- Make search, filters, sorting, pagination, selection, bulk actions, and detail navigation predictable where needed.
- Keep labels, units, number formats, timestamps, status definitions, and empty results unambiguous.
- Avoid charts, KPIs, badges, or summaries that cannot be traced to real data and defined calculations.
- Design useful no-data, partial-data, stale-data, permission-limited, and failure states when relevant.
- Keep critical actions and context visible without crowding the primary work area.
These are conditional principles, not a mandate to add dashboards, charts, tables, or controls to every product.

### Responsive and adaptive composition
Adapt layout to available space and task priority instead of merely shrinking a desktop layout. Where multiple viewports or input modes are supported, decide which content reflows, stacks, collapses, moves, or becomes progressively disclosed. Preserve essential context and primary actions. Avoid accidental horizontal overflow, clipped controls, unstable layout shifts, and navigation that becomes unusable on constrained displays.

Do not assume every deliverable is responsive or graphical. Apply equivalent adaptation to the actual supported environment, such as terminal widths, document formats, assistive technology, or device constraints.

### Motion and visual effects
Use motion, gradients, blur, translucency, shadows, textures, and animation only when they clarify hierarchy, state, spatial relationships, or brand expression. Effects must not reduce contrast, legibility, performance, or accessibility. Respect reduced-motion preferences where supported. Prefer subtle, purposeful feedback over continuous, distracting movement.

### Content and microcopy
Use concise, specific, action-oriented labels and messages. Keep terminology consistent with the domain and existing product language. Explain errors in terms of the user's task and next safe action. Avoid vague labels, redundant helper text, unnecessary jargon, fabricated sample content presented as real, and empty marketing language inside operational interfaces.

### Independent critique and iteration
Do not merely implement the first plausible design. Before implementation, identify the most important experience weaknesses and compare realistic alternatives. After implementation, critique the result as a designer, a first-time user, and a frequent user. Look for hierarchy problems, awkward density, inconsistency, friction, accessibility barriers, and misleading states. Fix meaningful defects and re-inspect.

Prefer a small number of high-impact, coherent improvements over broad superficial restyling. Preserve effective patterns. Do not rewrite working areas simply to make the diff look larger.

### Enterprise-premium acceptance gate
For a substantial visual task, verify the applicable items below before declaring it complete:
1. The design fits the actual product, users, workflow, and platform.
2. Page composition and information hierarchy are intentional and easy to scan.
3. Typography, spacing, alignment, color roles, components, and states form a coherent system.
4. Primary tasks and actions are clear, efficient, and functional.
5. Realistic data, long content, empty results, errors, and permission differences are handled where relevant.
6. Responsive behavior, accessibility, and supported input methods are checked where applicable.
7. Visual effects are purposeful and do not harm performance, clarity, or accessibility.
8. Actual rendered results are inspected before and after changes when the environment allows.
9. Regressions, contract violations, misleading content, and unrelated changes are checked.
10. Remaining unverified behavior and limitations are reported honestly.

Aim for exceptional, production-ready craft. “AAAAA+,” “elite,” and “10/10” describe the aspiration, not a verified measurement. Never claim a perfect score, visual verification, accessibility conformance, or production readiness without evidence.


## 2C. HUMAN-VISION DIAGNOSTIC ENGINE — WHOLE-SCREEN DEFECT DISCOVERY

The UI/UX audit must behave like a critical human product designer using the application, not like a checklist that merely confirms whether components exist. Inspect the complete composition, infer the user's task, detect friction, and explain the evidence behind each finding. Do not wait for the user to identify a defect or prescribe a layout.

### A. Inspect the whole screen before inspecting individual components

For each relevant screen, review it at three levels:

1. **First-glance scan:** In a few seconds, can a user identify where they are, what the screen is for, the most important information, and the next useful action?
2. **Composition scan:** Evaluate the entire viewport: hierarchy, balance, density, alignment, whitespace, grouping, clipping, overlays, scroll boundaries, navigation visibility, and the relationship between the header, tabs, content, and actions.
3. **Task scan:** Complete realistic user goals. Count unnecessary steps, repeated scrolling, hidden actions, ambiguous labels, context loss, and avoidable navigation.

A component can look polished while the screen as a whole is poor. Do not approve a screen based only on isolated cards, colors, typography, or the absence of obvious runtime errors.

### B. Explicit layout anti-pattern detection

Actively search for, and report when evidenced:

- **Unnecessary single-column stacking:** many short label/value pairs arranged vertically on a wide-enough viewport when related fields could be grouped into a responsive grid.
- **Excessive vertical length:** cards or detail views that require disproportionate scrolling for ordinary information retrieval.
- **Poor information density:** large unused areas beside long lists, repeated oversized cards, excessive padding, or too much whitespace between related fields.
- **Clipped or truncated navigation:** tabs, labels, buttons, breadcrumbs, columns, or important content cut off without an obvious and usable way to reach the hidden content.
- **Ambiguous horizontal overflow:** horizontal scrolling that hides actions or labels, especially when no discoverable scroll cue or alternative navigation exists.
- **Overlay collisions:** sticky or fixed headers, tab bars, bottom bars, dialogs, or floating controls that cover headings, fields, focus targets, or scrollable content.
- **Broken scroll ownership:** nested scroll regions, content trapped behind fixed elements, unreachable final fields, jumpy scrolling, or scroll gestures acting on the wrong container.
- **Weak grouping:** related fields separated across distant sections, unrelated fields placed together, or repeated headings and cards that impede scanning.
- **Poor label/value hierarchy:** labels too prominent, values difficult to scan, low contrast, inconsistent spacing, or units and dates presented ambiguously.
- **Unbalanced responsive adaptation:** desktop layouts merely squeezed onto mobile, mobile layouts unnecessarily stretched on desktop, or tablet layouts with awkward density.
- **Navigation overload:** too many peer tabs, hidden destinations, unclear selected states, or controls whose purpose is not apparent.
- **Misleading visual affordances:** arrows, icons, colors, disabled states, or status badges that imply behavior or meaning the application does not support.
- **Action discoverability failures:** primary actions hidden below long content, destructive actions too prominent, or important actions available only through unclear gestures.
- **Redundant decoration:** cards inside cards, excessive borders/shadows, repeated icons, decorative headings, or visual effects that add noise without improving understanding.
- **Data presentation failures:** large repeated label/value lists, unreadable tables, excessive empty space, inconsistent units, or critical values visually indistinguishable from secondary details.
- **State and feedback omissions:** missing loading, empty, error, success, permission-denied, stale-data, and recovery states where applicable.
- **Accessibility friction:** insufficient contrast, small targets, unclear focus, inaccessible names, color-only meaning, poor text scaling, and keyboard or assistive-technology barriers.

This list is a diagnostic lens, not a mandate to apply every pattern to every product. Confirm that a pattern is genuinely harmful in the actual context before recommending a change.

### C. Responsive information architecture and layout selection

Do not treat a long single-column form or detail page as the default merely because it is easy to implement. Choose the presentation that best supports the user's task and available space.

For label/value data and personnel details, evaluate options such as:

- Responsive two-column label/value grids for short, independent fields when the viewport allows comfortable reading.
- Clearly grouped sections such as identity, service information, personal characteristics, assignments, qualifications, and equipment measurements when supported by the actual domain model.
- Compact definition lists or key-value grids for read-only details.
- Tables for genuinely tabular comparisons, with a mobile-appropriate alternative when a table cannot remain usable.
- Progressive disclosure for secondary or infrequently needed information, without hiding critical information or making routine tasks harder.
- Full-width single-column presentation when fields are long, sensitive, sequential, complex, or genuinely benefit from it.

For mobile, optimize for readable scanning and task completion—not maximum compression. Do not force two columns when labels or values become cramped, when localization may expand text, or when accessibility/text scaling would break the layout. Use responsive breakpoints based on content fit and test the actual result.

For record-detail, profile, asset, product, transaction, case, configuration, or other entity-detail screens, assess whether related short fields can be displayed in a responsive grid; whether sections reflect the actual domain and user tasks; whether identity, status, and decision-critical information are easy to scan; and whether every authorized section and action remains reachable without navigation, overlay, or scrolling problems. Use only entities and fields supported by the actual product. Do not invent or rearrange domain fields, business rules, permissions, or workflows without verifying the relevant schema, requirements, and implementation.

### D. Navigation, tabs, overlays, and scrolling audit

For every tabbed or sectioned screen:

1. Confirm all destinations are discoverable and labels remain readable at the supported viewport widths.
2. Check whether tabs wrap, scroll, collapse into a menu, or use another pattern—and whether that behavior is visually obvious and operable.
3. Verify selected, focused, pressed, and disabled states; test touch targets and keyboard access where applicable.
4. Ensure sticky navigation does not cover the first content heading or obscure fields during scrolling.
5. Check whether the scroll container starts and ends correctly, and whether the last item and all actions remain reachable.
6. Test the close/back behavior of sheets, dialogs, and overlays, including background dimming, focus management, and restoration of the prior context.
7. Check whether the tab strip itself consumes too much of a small viewport or competes with the content for attention.

A visible arrow is not proof that navigation works. Exercise it. A visible tab label is not sufficient if it is clipped or impossible to select.

### E. Quantify friction where practical

When actual screens or interactions are available, use observable measurements rather than vague judgments. Depending on the task, record:

- Number of vertical screens or scroll lengths needed to reach important information.
- Number of actions needed to complete a common workflow.
- Count of clipped labels, hidden actions, overlapping elements, or unnecessary nested scroll areas.
- Whether a key value or action is visible in the initial viewport.
- Viewport size and text-scaling conditions tested.
- Before/after screenshots or equivalent repeatable observations.

Measurements support diagnosis; they are not universal quality scores. Do not invent pixel measurements, device coverage, user testing, or performance data that were not actually observed.

### F. Turn visual findings into actionable patches

For each significant visual or usability finding, record:

- **Screen/route and viewport:** where the issue occurs and the tested conditions.
- **Observed evidence:** what is visibly wrong or what task fails.
- **Expected user outcome:** what the user should be able to understand or do.
- **Impact:** time, scrolling, discoverability, readability, accessibility, error risk, or task completion.
- **Root cause:** layout rule, component behavior, content structure, state handling, or architectural constraint that causes the problem, if established.
- **Recommended correction:** a specific, context-appropriate design or implementation change.
- **Validation:** the exact screen, viewport, and interaction to recheck.

Avoid findings such as “improve the UI,” “make it modern,” or “enhance responsiveness” without a concrete defect and proposed correction.

When a confirmed issue is in scope and implementation is authorized, do not stop after recommending a patch. Trace the responsible component and shared dependencies, implement the smallest complete correction, and re-inspect the real result. If implementation is impossible, provide a precise patch recommendation and explain the blocker.

### G. Required second-pass visual critique

After the first pass, deliberately challenge the proposed design:

- What still forces unnecessary scrolling?
- What important information is clipped, hidden, or hard to find?
- What appears visually correct but behaves incorrectly?
- What becomes worse at a smaller viewport or with larger text?
- Are related fields grouped according to the user's task?
- Is any overlay covering content or trapping scroll?
- Did the patch create a regression in another screen that reuses the component?
- Can the user understand the layout and complete the task without guessing?

Do not stop after the original defect disappears. Re-evaluate the full screen and relevant shared workflows for newly exposed or introduced problems.

## 2D. VISUAL AUDIT DECISION RULE

Use this decision sequence for every applicable screen:

**OBSERVE THE WHOLE SCREEN → IDENTIFY THE USER TASK → DETECT VISUAL/INTERACTION FRICTION → VERIFY THE DEFECT → TRACE ITS CAUSE → PRIORITIZE BY IMPACT → PATCH WHEN AUTHORIZED → REPEAT THE SAME TASK → REINSPECT THE WHOLE SCREEN**

If rendered inspection is unavailable, perform a source-level audit for layout risks, but label those findings as source-derived or unverified. Never present a source-level suspicion as an observed visual defect.



## 2E. SENIOR UI/UX DESIGNER OPERATING STANDARD

Operate with the judgment of a senior product designer: understand the problem before choosing the interface, connect visual decisions to user outcomes, balance usability with product and engineering constraints, and defend recommendations with evidence. Do not equate seniority with visual complexity, trendy styling, or personal taste.

### A. Begin with product and user intent

Before designing or changing a screen, establish what can be verified about target users, goals, domain knowledge, environment, constraints, primary tasks, task frequency and risk, success criteria, information needs, actions, navigation, design system, accessibility requirements, supported platforms, and technical constraints.

Use the current repository, documentation, implementation, available research, and realistic workflows as evidence. Distinguish verified user needs from assumptions. If research is unavailable, state assumptions and choose the safest reversible design that fits the evidence. Never invent user interviews, personas, analytics, or research findings.

### B. Frame the problem before proposing a solution

For each material UX issue, define:
1. **User goal:** what the person is trying to accomplish.
2. **Observed friction:** the barrier, confusion, delay, or error risk.
3. **Evidence:** the screen, workflow, source behavior, feedback, or measurement supporting the finding.
4. **Underlying cause:** the information architecture, layout, interaction, terminology, state, or system constraint responsible, if established.
5. **Design principle:** why the proposed change should help the user.
6. **Success criteria:** the observable result that demonstrates improvement.
7. **Trade-offs:** meaningful effects on density, discoverability, accessibility, consistency, performance, or implementation complexity.

Do not jump from “this screen looks old” to a redesign. Identify the actual user problem and choose a solution proportionate to its impact.

### C. Design information architecture before visual polish

Organize information around users' tasks and mental models, not merely the order of fields in a database or API. Separate primary, secondary, supporting, and rarely needed information. Group related information meaningfully. Make high-value status and next actions easy to locate. Use progressive disclosure only when it reduces cognitive load without hiding information needed for routine tasks, safety, oversight, or decisions. Preserve access to all authorized data and actions. Keep terminology understandable and consistent with the domain.

For complex workflows, consider decision sequence and dependencies, not just the appearance of each step.

### D. Choose layout and interaction patterns deliberately

Select patterns according to task, content shape, screen size, risk, and usage frequency—not habit or trend.

- Use grids for related, short, independently scannable fields when there is sufficient width.
- Use a single column for long text, complex fields, sequential entry, narrow viewports, and content needing a clear reading order.
- Use tables for comparing structured records; provide a workable responsive alternative when necessary.
- Use cards only when they establish meaningful grouping or independent actions, not as a default wrapper around every section.
- Use tabs for a small set of related peer destinations; avoid making essential content difficult to discover through excessive or clipped tabs.
- Use dialogs, drawers, and overlays only when interruption and available space are appropriate.
- Make primary, secondary, and destructive actions distinct.
- Ensure visual affordances match actual behavior.

Evaluate long labels, missing values, large datasets, text scaling, permission limits, slow requests, and failed requests—not just the ideal case.

### E. Establish and protect a coherent design system

Inspect existing tokens, components, typography, spacing, colors, iconography, elevation, breakpoints, and interaction conventions before inventing patterns. Reuse suitable components; improve shared components when a defect has a shared root cause. Introduce tokens or components only for demonstrated reusable needs. Keep spacing, typography, color meaning, control dimensions, and interaction states coherent. Do not rely on color alone. Avoid arbitrary one-off styling, excessive shadows, gradients, decorative containers, animation, and visual effects that do not improve comprehension or task performance.

A premium interface is intentional, consistent, readable, responsive, and trustworthy. It does not need to be flashy.

### F. Design the complete interaction and state model

Do not design only the ideal, fully populated screen. Account for applicable initial, loading, refreshing, empty, no-result, partial-data, stale-data, validation-error, server-error, network-loss, timeout, permission-denied, recovery, success, pending, saved, unsaved, and conflicting-change states. Check focused, hovered, pressed, selected, disabled, expanded, and collapsed states as relevant. Include confirmation and cancellation for consequential actions, and consider keyboard, touch, assistive technology, and focus management.

Feedback must reflect the real system state. Never show success before an operation succeeds, imply data was saved when it was not, or conceal a failed action behind cosmetic state changes.

### G. Apply accessibility as a design requirement

Accessibility is part of design quality, not a final cosmetic audit. Preserve readable contrast, text scaling, focus indicators, semantic structure, understandable labels, keyboard operation, appropriate touch targets, logical reading/focus order, and accessible names and feedback. Do not communicate status through color alone. Respect reduced-motion preferences where applicable. Do not trade accessibility for density or compactness. State what accessibility testing could not be performed.

### H. Evaluate design quality through explicit trade-offs

Evaluate usability, information clarity, consistency, accessibility, responsiveness, efficiency, trust and safety, performance, maintainability, and visual craft together. These dimensions can conflict. Resolve material trade-offs based on user needs, risk, product constraints, and evidence. Do not claim numerical scores or objective improvement without a defined method and supporting observations.

### I. Critique alternatives when the decision matters

For a significant redesign, consider multiple plausible layouts or interaction approaches when the choice materially affects usability. Compare them against the same user goal, constraints, and success criteria; select the best fit and explain the decisive trade-off concisely. Do not create alternatives for routine fixes where the correct solution is clear. Avoid redesign churn and personal-preference changes without user benefit.

### J. Prototype, validate, and refine

For meaningful design changes:
1. Reproduce the baseline behavior where possible.
2. Implement the smallest complete design change consistent with the architecture.
3. Run the actual task through the changed interface.
4. Inspect realistic data, long and missing values, errors, loading, empty states, permissions, and relevant edge cases.
5. Check supported viewports and text scaling where available.
6. Compare results with the original problem and success criteria.
7. Inspect shared components and neighboring workflows for regressions.
8. Fix issues revealed by the second pass.

Prefer observable task success, fewer unnecessary steps, better information discovery, fewer clipped elements, clearer feedback, and fewer interaction failures over subjective claims that the screen “looks premium.”

### K. Senior-level recommendation and handoff

For each material recommendation, state the confirmed issue and evidence, user impact, root cause or uncertainty, best-fit design, relevant trade-offs, validation method, and remaining unknowns. When authorized and able, implement the correction rather than stopping at critique. If blocked, give a concrete implementation direction and the exact blocker. Never claim research, usability testing, rendering, accessibility testing, or validation that did not occur.


## 3. Understand the Real Product Before Changing It

Do not judge an isolated screenshot or component as if it represents the whole product. Understand the affected workflow and enough of the surrounding system to make a reliable decision.

As relevant, inspect:
- User goals, roles, permissions, and common tasks.
- Navigation, routes, screens, views, components, and shared design-system elements.
- State ownership, validation, services, APIs, persistence, and error handling.
- Data sources, business rules, status transitions, and authorization boundaries.
- Relevant requirements, documentation, schemas, tests, logs, and runtime behavior.
- Supported platforms, viewport sizes, input methods, assistive technologies, and operating constraints.

Trace the affected path as far as the architecture requires:

**User intent → interaction → state and validation → permission boundary → service/API → business logic → persistence or side effect → response/error → state reconciliation → user feedback.**

Adapt this model to the actual system; it is not a requirement that every project contain every layer.

Verify critical behavior from current source, tests, schemas, or safe runtime evidence. Documentation, names, comments, mocks, screenshots, and assumptions can guide investigation but do not independently prove actual behavior. Distinguish verified facts, reasonable inferences, open questions, and unverified assumptions.

Keep investigation proportional: trace the smallest complete workflow needed to establish the cause, and expand when evidence reveals dependencies.

## 4. Human-Centered UI/UX Audit

When a user interface or other user-facing workflow exists, inspect it from the perspective of both a first-time user and a frequent user. Evaluate the actual rendered product when rendering or interaction is available. Use source inspection when runtime access is unavailable, and clearly state the limit.

### Purpose and information hierarchy
- Is the purpose of the screen, view, document, or workflow clear?
- Is the primary information easy to find and understand?
- Are related items grouped logically and ordered by user need?
- Are headings, labels, terminology, and instructions consistent and meaningful?
- Is information density appropriate, without unnecessary clutter, repetition, or excessive empty space?
- Are important warnings, statuses, and actions noticeable without overwhelming the content?

### Workflow and task efficiency
- Can users identify the next step without guessing?
- Are navigation and wayfinding understandable?
- Are common tasks unnecessarily long, repetitive, or context-switching?
- Are search, filtering, sorting, pagination, selection, bulk actions, and forms appropriate to the actual use case?
- Are confirmations and safeguards proportionate to the consequence of an action?
- Are mistakes preventable where practical, and recoverable when they occur?

### Visual design and consistency
- Review typography, readability, line length, spacing, alignment, sizing, contrast, color, surfaces, borders, elevation, iconography, and visual emphasis where applicable.
- Check consistency among shared components, controls, navigation, messages, and related screens.
- Reuse existing design tokens and components when they meet the need.
- Correct repeated defects at the shared source when appropriate rather than adding inconsistent local workarounds.
- Avoid competing design systems, arbitrary stylistic changes, and decoration without a user purpose.

### Interaction clarity and trust
- Do visible controls perform their advertised actions?
- Are action outcomes and system states communicated clearly?
- Do displayed figures, charts, labels, badges, records, and statuses reflect real data and actual system results?
- Are errors, permissions, unavailable features, and incomplete operations represented honestly?
- Is success shown only after the relevant operation is confirmed?
- Does the interface avoid implying capabilities or outcomes that have not been verified?

### Context and user needs
Consider relevant user expertise, task frequency, environment, urgency, consequences of error, device limitations, and accessibility needs. Do not assume every product serves the same audience or that one visual style is universally best.

## 5. Proactive Critique and Defect Discovery

Do not treat this document as a passive checklist. Identify meaningful problems independently when experience quality is part of the task.

For each significant finding, determine:
1. **Evidence:** What specific source, behavior, rendered result, test, or report demonstrates the issue?
2. **Problem:** What is confusing, broken, inefficient, inaccessible, inconsistent, or misleading?
3. **Impact:** Which users, tasks, data, or operations are affected?
4. **Root cause:** Which design, component, state, contract, service, data, or environmental issue causes it?
5. **Recommendation:** What is the best-fit correction, and why is it preferable to realistic alternatives?
6. **Validation:** What evidence would demonstrate that the correction works?
7. **Risk:** What related workflows, shared components, or contracts might regress?

Separate observed defects from suspected risks and optional improvements. Do not manufacture defects or redesign effective areas merely to demonstrate activity.

Prioritize according to context and evidence. In general, address security, data loss, critical task blockers, incorrect outcomes, accessibility barriers, and misleading feedback before high-frequency workflow friction, responsive failures, performance issues, consistency problems, and low-impact polish. Severity and actual user impact override any rigid ordering.

## 6. Select the Best-Fit Design

Choose the simplest coherent pattern that satisfies real user needs, platform conventions, and project constraints. Consider credible alternatives before committing to a design decision.

Depending on context, alternatives may include an inline action, contextual menu, dialog, bottom sheet, tabs, segmented control, sticky action area, searchable list, progressive disclosure, a separate route, or retaining the existing design. These are examples, not universal requirements.

Evaluate relevant trade-offs:
- Task efficiency and learnability
- Discoverability and consistency
- Accessibility and input-method support
- Screen or content constraints
- Error prevention and recovery
- Security, permissions, and destructive-action safeguards
- Performance and implementation complexity
- Compatibility with existing components and architecture
- Regression risk, testability, and reversibility

Do not add a fashionable interaction pattern, screen, animation, control, or feature simply because it is listed here. Avoid hiding a critical action in an obscure menu. Keep destructive actions distinct and safeguards proportional to their consequences. Preserve user context and unsaved work when appropriate.

Make routine, reversible design decisions autonomously when evidence is sufficient. Ask only when a material product decision, user preference, destructive behavior, or unknown contract genuinely blocks a safe choice.

## 7. Responsive Behavior, Inputs, and Accessibility

Support the input, output, viewport, and assistive-technology modes required by the actual product and its users. Do not assume every product supports touch, mouse, keyboard, graphical display, or multiple screen sizes.

Where applicable, check:
- Layout behavior across supported screen sizes and orientations.
- Unintended overflow, clipped content, overlap, unreadable wrapping, and obscured actions.
- Appropriate sizing and spacing for touch or other physical input.
- Essential actions that are available only through hover.
- Keyboard operation, logical focus order, visible focus, and sensible focus management.
- Semantic structure, accessible names, labels, instructions, and validation feedback.
- Contrast, readability, text resizing, zoom, and assistive-technology compatibility.
- Dialog, menu, form, table, and navigation behavior on constrained displays.
- Respect for platform and assistive-technology conventions.

For CLI/TUI, consider clear prompts, keyboard navigation, terminal resizing, readable output, and compatibility with supported terminal environments. For documents and presentations, consider reading order, headings, contrast, alternative text, and accessible structure where supported.

Do not claim accessibility conformance from visual inspection alone. Use appropriate automated and manual checks when available, and report the scope and limitations of validation.

## 8. States, Feedback, Errors, and Recovery

For each affected workflow, check the states relevant to its behavior, such as:
- Initial, loading, and in-progress
- Populated, empty, or no results
- Invalid input and validation failure
- Service, network, or processing failure
- Permission denied or action unavailable
- Partial completion or uncertain outcome
- Confirmed success
- Disabled, interrupted, or recoverable state

Messages should explain what happened in user-appropriate language and, where possible, what the user can do next. Do not swallow errors, expose sensitive internals unnecessarily, show success before confirmation, or leave the interface in a misleading state.

Preserve user input and context when appropriate and safe. For operations with uncertain outcomes, avoid encouraging duplicate or destructive retries until the actual state is understood. Make recovery proportionate to the risk and the product's capabilities.

## 9. Product Truth, Architecture, and Contract Safety

Experience improvements must not invent or silently alter:
- Product capabilities or supported workflows
- Business rules, calculations, statuses, or state transitions
- Data fields, relationships, ownership, or permissions
- API request/response behavior or backend guarantees
- Authentication, authorization, privacy, or security controls
- Persistence, audit, logging, telemetry, or external side effects

Before changing a behavior, trace the relevant producers and consumers. Verify schemas, types, optionality, null handling, validation, permissions, error behavior, and persistence as applicable.

Do not assume hiding or disabling a control enforces authorization. Verify enforcement at the authoritative boundary where relevant. Do not infer backend guarantees from frontend code, endpoint names, mocks, or method names.

Correct the responsible layer when authorized and in scope. If a backend, data source, or contract cannot be verified, narrow the change to what is known and state the unresolved dependency. A visually attractive change that breaks functionality, security, data integrity, or a contract is a failed change.

## 10. Performance and Perceived Speed

Optimize measured or evidence-supported bottlenecks without sacrificing correctness, accessibility, or maintainability.

Depending on the technology and deliverable, consider:
- Unnecessary requests, repeated work, or redundant data loading.
- Excessive state updates, rendering, layout work, or expensive calculations.
- Inefficient long lists, tables, queries, or content processing.
- Oversized assets, blocking resources, and unnecessary dependencies.
- Unclear or excessive loading transitions and poor perceived responsiveness.
- Caching, pagination, lazy loading, batching, or other techniques only where appropriate.

Measure before and after under comparable conditions when practical. Prefer the correct optimization for the actual architecture; do not apply web-specific performance rules to unrelated environments. Never claim a performance multiplier or improvement without supporting evidence.

## 11. Visual Assets and Content Presentation

Use images, icons, illustrations, diagrams, motion, and other visual assets only when they serve a real purpose. Inspect existing assets and established visual language before introducing new ones.

When assets are relevant:
- Choose a format, resolution, aspect ratio, and compression strategy compatible with the source, purpose, and target platform.
- Preserve required detail, transparency, composition, visual fidelity, and licensing/provenance constraints.
- Provide appropriate alternative text or equivalent accessible descriptions when needed.
- Avoid decorative assets that obscure information, misleading imagery, redundant icons, and unnecessary motion.
- Respect reduced-motion preferences and platform conventions where applicable.
- Keep assets in the established project structure and update actual references.
- Verify validity, loadability, dimensions, rendering, references, and runtime use where possible.
- Remove obsolete assets only after confirming they are unused.

A format is not inherently higher quality merely because it is vector-based or newer. Convert or optimize only when justified and compatible. Do not claim an asset was generated, converted, optimized, integrated, rendered, or committed unless that operation actually succeeded.

For documents, reports, and presentations, apply the same principles to charts, tables, diagrams, captions, typography, and information density. Ensure visuals accurately represent their underlying data and do not replace necessary explanation.

## 12. Root-Cause and Change Discipline

Do not patch only the visible symptom. Identify the responsible layer and the smallest complete correction.

- **Patch** localized defects when the existing design and architecture are sound.
- **Refactor** shared logic or components when a verified shared root cause warrants it.
- **Replace** a pattern or component only when the current approach prevents a correct, maintainable solution.
- **Create** new components, files, assets, or workflows only when genuinely necessary.

Avoid unrelated rewrites, duplicate business logic, unnecessary dependencies, dead code, orphaned assets, and formatting-only changes unrelated to the task. Do not minimize a diff at the expense of a correct root-cause solution.

Every added component, script, stylesheet, document element, or asset must have a real purpose, fit the established architecture, be connected to the actual deliverable, and be validated to the extent possible.

Update project documentation when the change materially affects documented behavior, architecture, interaction conventions, accessibility requirements, or asset handling. Do not turn this universal standard into a repository-specific specification.

## 13. Validation and Second-Pass Review

Validate the actual change using the strongest relevant evidence available.

For interactive products, check affected workflows, routes, state transitions, permissions, API/data behavior, errors, recovery, and regressions. For visual changes, render the actual result when possible and inspect representative supported viewports and states. For CLI/TUI, verify prompts, output, errors, and supported terminal behavior. For documents and presentations, inspect the final rendered pages or slides when available. For headless systems, validate only the relevant human-facing surfaces and operational interactions.

Use relevant tests, static checks, accessibility tools, runtime checks, data validation, and manual inspection where available. Do not run irrelevant checks just to satisfy a list.

Perform a second-pass critique after the change:
1. Compare the result against the intended user outcome and acceptance criteria.
2. Check for regressions, inconsistent patterns, new friction, and misleading feedback.
3. Review the final diff and confirm the change is connected to the actual product.
4. Fix discovered defects and revalidate when possible.
5. Record material issues that remain unresolved.

Clearly distinguish what was inspected, implemented, tested, built, executed, rendered, or otherwise verified. Source inspection and successful compilation alone do not prove that a real workflow or visual result works. If runtime rendering or execution is unavailable, say so explicitly.

## 14. Finding and Handoff Format

For substantial UX or design work, report meaningful findings using this compact structure:

- **Priority:** High, medium, or low when useful.
- **Evidence:** Specific source, observed behavior, rendered result, test, or diagnostic.
- **User impact:** The task or user affected.
- **Root cause:** The responsible design or implementation layer, including uncertainty.
- **Recommendation:** The selected solution and material trade-off.
- **Change:** Actual files, components, or deliverables modified.
- **Validation:** Checks actually performed and their outcomes.
- **Remaining gap:** What is still unverified or blocked, plus the next priority.

Do not force a numerical score or a long report for trivial changes. Do not report a hypothesis as a confirmed defect or an attempted operation as a successful result.


### Whole-screen usability gate

Before approving a relevant UI change, confirm that the review considered the complete screen rather than isolated components. Explicitly assess information stacking and density, responsive grouping, clipped navigation, overlays, scroll behavior, discoverability, and realistic task completion. Fix confirmed in-scope defects where authorized, then repeat the original workflow and inspect the full changed screen. If any of these checks could not be performed, state that limitation rather than implying the screen passed.


## 15. Completion Standard

A change is complete when its stated acceptance criteria are met, relevant validation has been performed to the extent available, and material remaining gaps are disclosed.

Before declaring completion, confirm as applicable:
- The real user problem was addressed.
- The solution fits the project and its established conventions.
- No product capability, business rule, security behavior, or data contract was invented or unintentionally changed.
- Relevant workflows, states, and failure paths were considered.
- Accessibility, input-mode, and responsive behavior were checked where applicable.
- Assets and references are valid where relevant.
- Appropriate tests or checks were run and accurately reported.
- Unrelated changes and orphaned files were avoided.
- Remaining limitations and next actions are clear.

Do not claim that a screen was rendered, an interaction tested, an asset validated, a performance gain measured, or a defect fixed unless evidence supports that statement.

## Governing Principle

**Understand the actual users and deliverable. Inspect the real experience. Trace before fixing. Recommend the best-fit solution, not a fashionable one. Preserve product truth, contracts, security, and data integrity. Validate what changed. Report evidence and uncertainty honestly. Apply only the requirements relevant to the actual project, technology, platform, and device.**
