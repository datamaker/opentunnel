# Contributing to OpenTunnel

Thank you for your interest in contributing to OpenTunnel! This document provides guidelines for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors from all backgrounds.

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, versions)

### Suggesting Features

1. Open an issue with `[Feature]` prefix
2. Describe the use case
3. Explain the proposed solution

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Write/update tests if applicable
5. Run linting: `npm run lint`
6. Commit with clear message
7. Push and create a Pull Request

## Development Setup

### Server

```bash
cd server
npm install
npm run dev
```

### macOS Client

1. Open `clients/macos/VPNClient/VPNClient.xcodeproj` in Xcode
2. Configure signing with your Apple Developer account
3. Build and run

### Android Client

1. Open `clients/android` in Android Studio
2. Sync Gradle
3. Build and run

### Windows Client

1. Open `clients/windows/VPNClient.sln` in Visual Studio
2. Build solution

## Code Style

### TypeScript (Server)

- Use ESLint configuration
- Prefer `const` over `let`
- Use async/await over callbacks
- Add JSDoc comments for public APIs

### Swift (iOS/macOS)

- Follow Swift API Design Guidelines
- Use `guard` for early returns
- Prefer value types when possible

### Kotlin (Android)

- Follow Kotlin coding conventions
- Use coroutines for async operations
- Prefer data classes for models

### C# (Windows)

- Follow .NET naming conventions
- Use async/await patterns
- Document public APIs with XML comments

## Commit Messages

Format: `type(scope): description`

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(server): add session timeout configuration
fix(macos): resolve connection state not updating
docs(readme): update installation instructions
```

## Testing

### Server

```bash
cd server
npm test
```

### Clients

Test on actual devices when possible, especially for VPN functionality.

## Security

If you discover a security vulnerability, please email security@example.com instead of creating a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
