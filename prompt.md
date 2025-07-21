
# PROMPT: 

Please begin working on the next task in the project. 

Based on the expanded task list and complexity analysis, please:
1. Identify the highest priority task that should be worked on next
2. Consider task dependencies and logical development sequence
3. Select a task that is ready to be started (no blocking dependencies)
4. Provide a brief rationale for why this task was selected

Once you've identified the next task, please begin implementation by:
- Reviewing the task requirements and acceptance criteria
- Setting up any necessary files, folders, or project structure
- Writing the initial code, documentation, or configurations needed
- Following best practices and the technical approach outlined in the task expansion
- Creating any necessary tests or validation steps
- Documenting your progress and any decisions made during implementation

As you work on the task, please:
- Provide updates on your progress
- Flag any issues, blockers, or unexpected complexities you encounter
- Ask for clarification if any requirements are unclear
- Suggest improvements or alternative approaches if you identify better solutions

Please proceed with selecting and starting work on the next appropriate task from our project plan.


---

# Prompt: 

**Analyze the current @git-changes and do the following:**

1. Review each modified, added, or deleted file.
2. For each file, generate a clear, technically detailed, and concise commit message that explains *why* the change was made (not just what).
3. Group related files under a single commit if they serve the same purpose, but keep unrelated changes separated.
4. Stage all the relevant files.
5. Commit each change with the generated message.
6. Push the commits to the current branch.

**Output the plan before executing. Confirm with me if:**
* Any file change is ambiguous or unclear in purpose
* There are mixed concerns in one change (e.g., refactor + feature + fix)

**Use conventional commit syntax where appropriate** (e.g., `feat:`, `fix:`, `refactor:`).
