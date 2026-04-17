## Brief overview
  Global guidelines instructing Cline to always apply Robert C. Martin's Clean Code principles when writing, reviewing, or refactoring code in this project.

## Naming
  - Use intention-revealing, pronounceable, and searchable names for variables, functions, classes, and files.
  - Prefer descriptive names over comments; avoid abbreviations, encodings, and mental mapping (no single-letter names outside tiny scopes).
  - Classes should be nouns; functions should be verbs; keep naming consistent across the codebase.

## Functions
  - Keep functions small and focused — they should do one thing, at one level of abstraction.
  - Minimize arguments (prefer 0–2); avoid flag arguments by splitting into separate functions.
  - No side effects hidden behind innocent-looking names; command-query separation (functions either do or answer, not both).
  - Prefer early returns over deep nesting; avoid output arguments.

## Comments
  - Prefer expressive code over comments; comments should explain "why", never restate "what".
  - Remove commented-out code, redundant comments, and misleading/outdated comments.
  - Acceptable comments: legal notices, clarifying intent that code cannot express, TODOs with context, public API docs.

## Formatting and structure
  - Keep files, classes, and functions small; organize top-down so readers descend one level of abstraction at a time.
  - Group related code vertically; keep dependent functions close; variables declared near their usage.
  - Maintain consistent formatting; rely on the project's existing formatter/linter (Biome) rather than manual style choices.

## Error handling
  - Use exceptions rather than return codes; don't pass or return `null` — prefer empty collections, Option-like types, or explicit errors.
  - Wrap third-party APIs to keep error boundaries clean; error handling is one thing, so isolate it in dedicated functions.
  - Provide context with exceptions; never swallow errors silently.

## Classes and SOLID
  - Classes should be small with a single responsibility (SRP); high cohesion, minimal instance variables.
  - Follow Open/Closed, Liskov Substitution, Interface Segregation, and Dependency Inversion — depend on abstractions, not concretions.
  - Prefer composition over inheritance; hide implementation details and expose behavior.

## Testing and DRY
  - Treat tests as first-class code: follow F.I.R.S.T. (Fast, Independent, Repeatable, Self-validating, Timely).
  - One assert/concept per test where practical; keep tests readable with clear Arrange-Act-Assert structure.
  - Eliminate duplication (DRY) in production and test code; extract shared setup and helpers.

## Refactoring workflow
  - Follow the Boy Scout Rule: leave code cleaner than you found it, with small incremental improvements alongside feature work.
  - When a violation is found, propose the smallest safe refactor (rename, extract function, split class) rather than a sweeping rewrite.
  - Ensure tests pass before and after each refactor; never mix behavioral changes with pure refactors in the same step.
