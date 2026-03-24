# Contributing

This handbook is written for practitioners in federal data science environments. Contributions that improve accuracy, add platform-specific detail, or extend coverage to new topics are welcome.

---

## Before You Start

1. **Read the style guide** — [`docs/STYLE_GUIDE.md`](docs/STYLE_GUIDE.md) defines the voice, and it is non-negotiable. Content that reads like a blog post, a textbook, or AI-generated prose does not fit this handbook.
2. **Read the chapter spec** — [`docs/CHAPTER_WRITING_SPEC.md`](docs/CHAPTER_WRITING_SPEC.md) covers structure, code example requirements, and exercise format.

---

## Types of Contributions

### Content (Chapters and Platform Guides)

Each chapter follows a consistent structure defined in the chapter spec. If you are adding a new chapter or extending an existing one:

- Use the templates in `templates/` as starting points
- Include working Python code examples in `code-examples/python/`
- Include exercises with solutions in `exercises/`
- Cover all five platforms where the topic applies

### Code Examples

Code examples must run on the platforms they describe — not on an unconstrained local machine. If your example requires packages, verify they are available on the target platform's approved package list.

### Platform Guides

Platform guides are self-contained references. If you are adding detail to a platform guide, include:

- Platform-specific configuration in `config/`
- Connection test scripts in `scripts/`
- Any supporting documentation in `docs/`

### Security and Compliance Reference Code

The `security-compliance/` directory contains reference implementations for federal security patterns (CAC/PIV authentication, RBAC, multi-classification, compliance frameworks). Contributions here should follow the existing module structure and include appropriate documentation.

### Docker Environment

The local development environment in `docker/` mirrors federal platform constraints. Changes to Dockerfiles or service configurations should maintain this fidelity — do not add services or configurations that would not exist in a federal IL4/IL5 environment.

---

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes following the style guide and chapter spec
4. Submit a pull request with a clear description of what you changed and why

Pull requests that introduce placeholder text, banned phrases from the style guide, or generic examples disconnected from federal platform realities will be rejected at review.

---

## Code of Conduct

Be respectful, be constructive, and remember that this handbook exists to help practitioners do real work in a difficult environment. Contributions should make that work easier.
