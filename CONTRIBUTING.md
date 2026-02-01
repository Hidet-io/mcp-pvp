# Contributing to mcp-pvp

Thank you for your interest in contributing to mcp-pvp! This document provides guidelines and instructions for contributing to the project.

---

## Development Setup

### Prerequisites

- Python 3.11 or higher
- [Poetry](https://python-poetry.org/docs/#installation) for dependency management
- Git

### Getting Started

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/mcp-pvp.git
cd mcp-pvp
```

2. **Install dependencies with Poetry**

```bash
# Install all dependencies including dev and optional extras
poetry install --all-extras --with dev

# Or use the Makefile
make install-all
```

3. **Set up pre-commit hooks**

```bash
poetry run pre-commit install
```

---

## Development Workflow

### Using the Makefile

We provide a Makefile for common development tasks:

```bash
make help          # Show all available commands
make test          # Run tests
make test-cov      # Run tests with coverage
make lint          # Run ruff linter
make format        # Format code with ruff
make typecheck     # Run mypy type checker
make check         # Run all checks (lint + format + typecheck + test)
make clean         # Clean build artifacts
```

### Code Quality Standards

All code must pass the following checks before submission:

1. **Linting** - `make lint`
2. **Formatting** - `make format`
3. **Type checking** - `make typecheck`
4. **Tests** - `make test`

**Before submitting a PR, run:**

```bash
make check
```

---

## How to Contribute

### Reporting Issues

- Check existing issues first
- Provide clear reproduction steps
- Include version information
- For security issues, see [SECURITY.md](SECURITY.md)

### Proposing Features

- Open an issue first to discuss
- Explain the use case
- Consider backward compatibility
- Align with project goals (privacy-first, local-first)

### Pull Requests

1. **Fork and clone:**
   ```bash
   git clone https://github.com/<your-username>/mcp-pvp.git
   cd mcp-pvp
   ```

2. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Install development dependencies:**
   ```bash
   pip install -e ".[dev]"
   pre-commit install
   ```

4. **Make changes:**
   - Follow coding standards (see below)
   - Add tests for new functionality
   - Update documentation

5. **Run checks:**
   ```bash
   ruff check .
   ruff format .
   mypy src/
   pytest
   ```

6. **Commit:**
   ```bash
   git add .
   git commit -m "feat: add feature X"
   ```
   Use conventional commits:
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation
   - `test:` tests
   - `refactor:` code refactoring
   - `chore:` maintenance

7. **Push and create PR:**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a pull request on GitHub.

## Coding Standards

### Python

- **Python version:** 3.11+
- **Style:** Ruff (lint + format)
- **Type hints:** Full type annotations required (mypy strict mode)
- **Docstrings:** Required for public APIs
- **Line length:** 100 characters

### Structure

- Keep functions small and focused
- Favor pydantic models over dictionaries
- Use structured logging (structlog)
- **Never log raw PII**

### Testing

- Use pytest
- Aim for high coverage (>80%)
- Test critical paths: capabilities, policy, store, tokens
- Use freezegun for time-based tests
- Mock external dependencies

### Security

- Never expose raw PII in logs or errors
- Default-deny for new features
- Validate all inputs
- Use constant-time comparisons for secrets
- Document security implications

## Areas We Welcome Contributions

### High Priority

- **Detector modules:** High-precision PII detectors (low false positives)
- **Policy primitives:** New policy constructs (time-based, conditional)
- **Examples:** Real-world usage examples (CRM, ticketing, etc.)
- **Documentation:** Tutorials, guides, API docs
- **Tests:** Improve coverage and edge cases

### Medium Priority

- **Encrypted persistence:** SQLite + encryption at rest
- **MCP SDK integration:** Once official Python SDK is stable
- **Proxy mode:** Transparent PVP injection for existing agents
- **Performance:** Optimization for large-scale workloads

### Ideas Welcome

- Custom sink types
- Advanced audit queries
- Integration examples (LangChain, Semantic Kernel, etc.)
- CI/CD improvements

## Code Review Process

1. Automated checks must pass (CI)
2. At least one maintainer review required
3. Address feedback or explain rationale
4. Maintainers merge approved PRs

## Community Guidelines

- Be respectful and inclusive
- Focus on technical merit
- Assume good intentions
- Help others learn

## Development Setup

### With uv (recommended)
```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install
uv venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
uv pip install -e ".[dev]"

# Or use Makefile
make install-dev
```

### With pip
```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests
```bash
pytest
pytest -v  # verbose
pytest -k test_caps  # run specific tests
pytest --cov  # with coverage
```

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.

## Questions?

Open a discussion on GitHub or reach out to the maintainers.

Thank you for contributing to a more privacy-preserving LLM ecosystem!
