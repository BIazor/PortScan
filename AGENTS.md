# Autonomous Development and Verification Rules

## 1. Core Development Principles

For every development task, follow the complete development workflow defined below.

- Prioritize correctness, reliability, maintainability, and security.
- Understand the existing project before making changes.
- Make the smallest reasonable changes necessary to accomplish the task.
- Preserve existing architecture, coding conventions, and design patterns unless there is a clear reason to change them.
- Do not introduce unnecessary dependencies, abstractions, files, or complexity.
- Never assume an implementation works simply because the code was written.
- Verify actual application behavior before declaring a task complete.
- Do not silently skip testing or conceal failures.

## 2. Project Inspection

Before modifying anything:

1. Inspect the existing project structure.
2. Identify the application's framework, language, build system, and dependencies.
3. Read relevant project documentation, including README.md, AGENTS.md, and configuration files.
4. Identify important entry points, existing components, services, and related functionality.
5. Examine existing implementations before creating replacements.
6. Identify existing tests and established testing procedures.
7. Check the current Git branch and working tree for uncommitted changes.

Never overwrite existing work or assume that files are safe to modify without inspecting them first.

## 3. Documentation and Research

Use Context7 MCP when working with external libraries, frameworks, APIs, or tools.

- Resolve the correct library documentation before querying it.
- Prefer official and current documentation.
- Verify API signatures, supported parameters, configuration options, and recommended usage.
- Do not rely on outdated knowledge when current documentation is available.
- Do not invent APIs, methods, or configuration options.
- If documentation is unavailable, explicitly state that limitation.

For unfamiliar technologies, research the relevant implementation details before proceeding.

## 4. Implementation Planning

Before making changes, produce a short implementation plan.

The plan should identify:

- The problem being addressed.
- The files or components expected to change.
- The intended implementation approach.
- Potential risks or compatibility concerns.
- How the changes will be tested.

Keep the plan proportional to the task. Small changes should have short plans.

After planning, proceed with implementation unless clarification or authorization is required.

## 5. Implementation Rules

- Make focused, minimal changes.
- Preserve existing functionality unless the task explicitly requires changing it.
- Follow existing naming conventions, formatting, and project architecture.
- Reuse existing components and utilities when appropriate.
- Avoid duplicating existing functionality.
- Handle errors and unexpected input appropriately.
- Consider security implications when modifying authentication, authorization, networking, file handling, or user input.
- Do not hardcode credentials, API keys, passwords, or other secrets.
- Never place sensitive tokens in source code, logs, commits, or documentation.
- Do not modify unrelated files.

If a larger restructuring becomes necessary, explain why before proceeding.

## 6. Git and Version Control Safety

Use GitHub MCP and available Git tools when repository operations are needed.

Before making changes:

- Inspect the current branch.
- Check for uncommitted changes.
- Preserve user modifications.
- Avoid overwriting existing work.

During development:

- Prefer a separate feature branch for substantial changes.
- Keep changes logically organized.
- Do not commit unrelated modifications.
- Never force-push or rewrite shared Git history without explicit authorization.
- Never commit secrets, credentials, or sensitive local configuration files.

After implementation:

- Review the changes using Git diff.
- Verify that only intended files were modified.
- Summarize the changes.

Do not push, merge, delete branches, or modify remote repositories unless explicitly authorized by the user.

## 7. Application Execution and Testing

After implementation, verify that the application actually works.

### Application startup

1. Identify the correct startup and build commands.
2. Install dependencies only when necessary.
3. Build the application when an appropriate build process exists.
4. Start the application using the project's existing development or execution workflow.
5. Verify that the application starts successfully.
6. Check terminal output for errors, warnings, and failed processes.

Do not assume that a successful build means the application works correctly.

### Functional testing

Test the actual application rather than relying exclusively on static code inspection.

- Test the functionality requested by the user.
- Exercise relevant user interactions.
- Verify expected outputs and state changes.
- Test navigation, forms, buttons, authentication, and other relevant functionality.
- Check important edge cases and error handling.
- Verify that existing functionality has not regressed.

Use the testing tools appropriate to the project.

## 8. MCP Tool Requirements

Use the configured MCP servers when they are relevant to the task.

### Playwright MCP

Use Playwright for actual browser interaction and end-to-end verification.

- Navigate to the running application.
- Inspect the rendered page.
- Interact with buttons, forms, menus, and other relevant elements.
- Verify navigation and user workflows.
- Confirm that expected content and behavior appear in the browser.
- Capture screenshots when useful for visual verification.

Do not declare UI functionality successful based only on source code inspection.

### Context7 MCP

Use Context7 to retrieve current documentation for external libraries and frameworks.

Do not invent library APIs or assume that previously learned usage is still correct.

### GitHub MCP

Use GitHub MCP for authorized repository operations.

- Inspect repository metadata and branches.
- Read relevant files and commit history.
- Review issues and pull requests when relevant.
- Create branches, commits, and pull requests only when authorized.
- Verify remote operations through actual tool responses.

### Chrome DevTools MCP

Use Chrome DevTools for browser debugging and deeper inspection.

When applicable:

- Inspect browser console messages.
- Identify JavaScript exceptions and runtime errors.
- Inspect failed network requests.
- Examine request and response details.
- Inspect application state and rendered elements.
- Use performance inspection when relevant.

Playwright and Chrome DevTools serve complementary purposes. Use both when the task benefits from browser interaction and deeper debugging.

## 9. Error Handling and Iterative Verification

If a test fails:

1. Identify the failure and gather relevant diagnostic information.
2. Determine whether the issue originates from the implementation, environment, configuration, or an external dependency.
3. Make the smallest appropriate correction.
4. Restart or rebuild the application if necessary.
5. Repeat the failed test.
6. Recheck related functionality for regressions.

Continue until the issue is resolved or a genuine blocker prevents further progress.

Never hide failed tests or report unsuccessful operations as successful.

If a tool is unavailable, explain the limitation and use an appropriate alternative when possible.

## 10. Completion Requirements

A development task is not complete simply because implementation has finished.

Before declaring completion:

- Confirm the application builds or runs successfully, where applicable.
- Confirm the requested functionality works.
- Complete relevant functional tests.
- Review browser console errors when applicable.
- Review failed network requests when applicable.
- Check for unintended changes.
- Confirm that no credentials or secrets were exposed.
- Identify any remaining limitations.

If something could not be tested, explicitly identify it.

## 11. Final Response Format

At the end of every development task, provide a concise report containing:

### Implementation Summary
- What was implemented or fixed.
- How the implementation addresses the request.

### Files Changed
- List each modified or created file.
- Briefly explain what changed in each file.

### Testing Performed
- Build or compilation results.
- Application startup results.
- Functional tests performed.
- Playwright browser verification.
- Chrome DevTools console and network inspection, when applicable.

### Results
Clearly distinguish between:
- PASS: Successfully tested and verified.
- FAIL: Tested and unsuccessful.
- NOT TESTED: Not executed or unable to verify.

### Remaining Issues
- Known bugs.
- Incomplete functionality.
- Environmental limitations.
- Tests that could not be performed.

Never claim a feature works unless its behavior has been verified through appropriate testing.

## 12. User Authorization and Safety

The user's explicit instructions take priority over optional development improvements.

- Ask before performing destructive or irreversible operations.
- Do not delete user data, databases, files, branches, or repositories without authorization.
- Do not deploy to production without authorization.
- Do not modify production infrastructure or external services without authorization.
- Do not expose secrets or private information.
- Do not silently change the scope of the requested task.
- If an important requirement is ambiguous, ask for clarification rather than making a risky assumption.

## Final Principle

**Inspect before changing. Plan before implementing. Test before declaring completion.**

The objective is to deliver working, verified software rather than merely produce code that appears correct.