# Contributing to Security Framework

Thank you for your interest in contributing to the Security Framework! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Environment](#development-environment)
4. [Project Structure](#project-structure)
5. [Coding Standards](#coding-standards)
6. [Development Workflow](#development-workflow)
7. [Testing Guidelines](#testing-guidelines)
8. [Documentation Guidelines](#documentation-guidelines)
9. [Commit Message Convention](#commit-message-convention)
10. [Pull Request Process](#pull-request-process)
11. [Issue Reporting](#issue-reporting)
12. [Security Vulnerabilities](#security-vulnerabilities)
13. [License](#license)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please be respectful and constructive in all interactions.

### Our Standards

- **Be respectful**: Treat everyone with respect and kindness
- **Be inclusive**: Welcome people of all backgrounds and identities
- **Be collaborative**: Work together constructively
- **Be professional**: Maintain professional conduct in all communications
- **Focus on the work**: Keep discussions focused on technical matters

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **.NET 9 SDK** or later
- **Git** for version control
- **Visual Studio 2022** or **VS Code** (recommended IDEs)
- **Docker** (for containerized testing)
- **SQLite** tools (for database testing)

### Fork and Clone

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/your-username/SecurityFramework.git
   cd SecurityFramework
   ```
3. **Add upstream** remote:
   ```bash
   git remote add upstream https://github.com/original-owner/SecurityFramework.git
   ```

### First-Time Setup

1. **Restore dependencies**:
   ```bash
   dotnet restore
   ```

2. **Build the solution**:
   ```bash
   dotnet build
   ```

3. **Run tests**:
   ```bash
   dotnet test
   ```

4. **Verify setup**:
   ```bash
   dotnet run --project samples/BasicWebApi
   ```

## Development Environment

### Required Tools

- **.NET 9 SDK**: Latest stable version
- **Git**: Version 2.25 or later
- **Editor**: Visual Studio 2022, VS Code, or Rider

### Recommended Extensions (VS Code)

- C# Dev Kit
- GitLens
- EditorConfig for VS Code
- NuGet Package Manager
- Docker
- SQLite Viewer

### Environment Variables

For development, you may need to set:

```bash
# Optional: Custom test database path
export SECURITY_FRAMEWORK_TEST_DB="/tmp/security_test.db"

# Optional: Redis connection for integration tests
export REDIS_CONNECTION_STRING="localhost:6379"
```

## Project Structure

Understanding the project layout:

```
SecurityFramework/
├── src/                           # Source code
│   ├── SecurityFramework.Core/    # Core models and abstractions
│   ├── SecurityFramework.Data/    # Data access and EF Core
│   ├── SecurityFramework.Services/# Business logic and services
│   ├── SecurityFramework.Middleware/# ASP.NET Core middleware
│   ├── SecurityFramework.RealTime/# Optional SignalR/WebSocket
│   └── SecurityFramework.ML/      # Optional ML.NET features
├── tests/                         # All test projects
│   ├── Unit/                     # Unit tests
│   ├── Integration/              # Integration tests
│   └── Performance/              # Performance benchmarks
├── samples/                      # Example applications
├── patterns/                     # JSON pattern templates
├── docs/                         # Documentation
├── tools/                        # Build and development tools
└── scripts/                      # Automation scripts
```

### Key Directories

- **`src/SecurityFramework.Core/`**: Contains core models, abstractions, and extensions
- **`src/SecurityFramework.Services/`**: Business logic, threat detection, and scoring
- **`src/SecurityFramework.Data/`**: EF Core context, repositories, and migrations
- **`src/SecurityFramework.Middleware/`**: ASP.NET Core integration
- **`tests/`**: Comprehensive test suite with unit, integration, and performance tests
- **`samples/`**: Working examples for different use cases
- **`patterns/`**: JSON templates for threat detection patterns

## Coding Standards

### C# Style Guidelines

We follow the [.NET Framework Design Guidelines](https://docs.microsoft.com/en-us/dotnet/standard/design-guidelines/) with these specific rules:

#### Naming Conventions

```csharp
// PascalCase for classes, methods, properties
public class SecurityService
{
    public void AssessIpAddress() { }
    public string ThreatLevel { get; set; }
}

// camelCase for fields, parameters, local variables
private readonly ILogger _logger;
public void ProcessRequest(string ipAddress, int port) { }

// UPPER_CASE for constants
public const int MAX_THREAT_SCORE = 100;

// Interface names start with 'I'
public interface ISecurityService { }
```

#### File Organization

```csharp
// File header (if required)
// Using statements
using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

// Namespace
namespace SecurityFramework.Services
{
    // Class definition
    public class SecurityService : ISecurityService
    {
        // Constants
        private const int DefaultThreshold = 50;
        
        // Fields
        private readonly ILogger<SecurityService> _logger;
        
        // Constructors
        public SecurityService(ILogger<SecurityService> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }
        
        // Properties
        public bool IsEnabled { get; set; }
        
        // Methods (public first, then private)
        public async Task<ThreatAssessment> AssessAsync(string ipAddress)
        {
            // Implementation
        }
        
        private void LogThreat(string message)
        {
            // Implementation
        }
    }
}
```

#### Code Style Rules

**1. Braces and Indentation**
```csharp
// Use Allman style braces
if (condition)
{
    DoSomething();
}

// 4 spaces for indentation (no tabs)
public void Method()
{
    if (condition)
    {
        DoSomething();
    }
}
```

**2. Line Length**
- Maximum 120 characters per line
- Break long parameter lists appropriately

**3. Method Structure**
```csharp
public async Task<ThreatAssessment> AssessIPAsync(
    string ipAddress, 
    CancellationToken cancellationToken = default)
{
    // Validate parameters first
    if (string.IsNullOrWhiteSpace(ipAddress))
        throw new ArgumentException("IP address cannot be null or empty", nameof(ipAddress));
        
    // Early returns for simple cases
    if (IsWhitelistedIP(ipAddress))
        return ThreatAssessment.Safe;
        
    // Main logic
    var assessment = await PerformAssessmentAsync(ipAddress, cancellationToken);
    
    // Logging and cleanup
    _logger.LogInformation("Assessment completed for {IpAddress}", ipAddress);
    
    return assessment;
}
```

### Performance Guidelines

1. **Async/Await**: Use consistently for I/O operations
2. **Memory Efficiency**: Prefer `Span<T>` and `Memory<T>` for high-performance scenarios
3. **Caching**: Implement appropriate caching strategies
4. **Resource Disposal**: Use `using` statements and implement `IDisposable`

### Security Guidelines

1. **Input Validation**: Validate all external inputs
2. **Sanitization**: Sanitize data before logging or persistence
3. **Error Handling**: Never expose sensitive information in error messages
4. **Logging**: Log security events appropriately without leaking sensitive data

```csharp
// Good: Sanitized logging
_logger.LogWarning("Failed login attempt from IP {IpAddress}", 
    SanitizeForLogging(ipAddress));

// Bad: Potential data leakage
_logger.LogError("Authentication failed: {Error}", exception.ToString());
```

## Development Workflow

### Git Workflow

We use a **feature branch workflow**:

1. **Create feature branch** from `main`:
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b feature/threat-scoring-algorithm
   ```

2. **Make changes** and commit:
   ```bash
   git add .
   git commit -m "feat: implement advanced threat scoring algorithm"
   ```

3. **Keep branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

4. **Push and create PR**:
   ```bash
   git push origin feature/threat-scoring-algorithm
   ```

### Branch Naming Convention

- **Features**: `feature/description` (e.g., `feature/signalr-integration`)
- **Bug fixes**: `fix/description` (e.g., `fix/memory-leak-in-cache`)
- **Documentation**: `docs/description` (e.g., `docs/update-api-examples`)
- **Refactoring**: `refactor/description` (e.g., `refactor/extract-scoring-service`)
- **Performance**: `perf/description` (e.g., `perf/optimize-ip-lookup`)

### Daily Development

1. **Start with tests**: Write failing tests first (TDD approach)
2. **Implement incrementally**: Small, focused commits
3. **Run tests frequently**: Ensure nothing breaks
4. **Update documentation**: Keep docs current with code changes

## Testing Guidelines

### Test Structure

Our testing strategy includes:

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions
3. **Performance Tests**: Benchmark critical paths
4. **Security Tests**: Validate security controls

### Writing Unit Tests

```csharp
[TestClass]
public class SecurityServiceTests
{
    private readonly Mock<ILogger<SecurityService>> _loggerMock;
    private readonly Mock<IPatternService> _patternServiceMock;
    private readonly SecurityService _securityService;
    
    public SecurityServiceTests()
    {
        _loggerMock = new Mock<ILogger<SecurityService>>();
        _patternServiceMock = new Mock<IPatternService>();
        _securityService = new SecurityService(_loggerMock.Object, _patternServiceMock.Object);
    }
    
    [TestMethod]
    public async Task AssessIPAsync_ValidIP_ReturnsThreatAssessment()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var expectedAssessment = new ThreatAssessment { ThreatScore = 25 };
        
        // Act
        var result = await _securityService.AssessIPAsync(ipAddress);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual(25, result.ThreatScore);
    }
    
    [TestMethod]
    public async Task AssessIPAsync_NullIP_ThrowsArgumentException()
    {
        // Act & Assert
        await Assert.ThrowsExceptionAsync<ArgumentException>(
            () => _securityService.AssessIPAsync(null));
    }
}
```

### Test Naming Convention

- **Format**: `MethodName_Scenario_ExpectedBehavior`
- **Examples**:
  - `AssessIPAsync_ValidIP_ReturnsThreatAssessment`
  - `ValidateParameter_NullValue_ThrowsArgumentException`
  - `CalculateScore_HighThreatIP_ReturnsHighScore`

### Integration Test Example

```csharp
[TestClass]
public class SecurityMiddlewareIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    
    public SecurityMiddlewareIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }
    
    [TestMethod]
    public async Task Middleware_MaliciousIP_BlocksRequest()
    {
        // Arrange
        var client = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureTestServices(services =>
            {
                services.Configure<SecurityFrameworkOptions>(options =>
                {
                    options.DefaultThreatThreshold = 80;
                });
            });
        }).CreateClient();
        
        // Act
        var response = await client.GetAsync("/api/test");
        
        // Assert
        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
```

### Performance Testing

```csharp
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class SecurityServiceBenchmarks
{
    private SecurityService _service;
    
    [GlobalSetup]
    public void Setup()
    {
        // Initialize service
    }
    
    [Benchmark]
    [Arguments("192.168.1.1")]
    public async Task<ThreatAssessment> AssessIP(string ipAddress)
    {
        return await _service.AssessIPAsync(ipAddress);
    }
}
```

## Documentation Guidelines

### Code Documentation

Use XML documentation comments for public APIs:

```csharp
/// <summary>
/// Assesses the threat level of an IP address using machine learning-inspired algorithms.
/// </summary>
/// <param name="ipAddress">The IP address to assess. Must be a valid IPv4 or IPv6 address.</param>
/// <param name="cancellationToken">Token to cancel the operation.</param>
/// <returns>
/// A <see cref="ThreatAssessment"/> containing the threat score and recommended action.
/// </returns>
/// <exception cref="ArgumentException">Thrown when <paramref name="ipAddress"/> is null or invalid.</exception>
/// <exception cref="InvalidOperationException">Thrown when the service is not properly configured.</exception>
/// <example>
/// <code>
/// var assessment = await securityService.AssessIPAsync("192.168.1.1");
/// if (assessment.ThreatScore > 80)
/// {
///     // Block the request
/// }
/// </code>
/// </example>
public async Task<ThreatAssessment> AssessIPAsync(
    string ipAddress, 
    CancellationToken cancellationToken = default)
```

### README Updates

When adding features, update relevant README sections:

- **Installation instructions**
- **Configuration examples**
- **Usage examples**
- **API documentation links**

### API Documentation

For new public APIs, provide:

1. **Purpose and use cases**
2. **Parameter descriptions**
3. **Return value explanations**
4. **Exception scenarios**
5. **Code examples**
6. **Performance considerations**

## Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Build process or auxiliary tool changes

### Examples

```bash
# Feature addition
feat(security): implement advanced threat scoring algorithm

# Bug fix
fix(middleware): resolve memory leak in IP cache cleanup

# Documentation
docs(api): add examples for parameter security service

# Performance improvement
perf(scoring): optimize threat calculation for high-volume scenarios

# Breaking change
feat(api)!: redesign security assessment interface

BREAKING CHANGE: SecurityService.Assess() renamed to AssessAsync()
```

### Scope Guidelines

Common scopes:
- **core**: Core framework functionality
- **data**: Data access and persistence
- **middleware**: ASP.NET Core middleware
- **realtime**: SignalR/WebSocket features
- **ml**: Machine learning components
- **tests**: Test-related changes
- **docs**: Documentation updates
- **build**: Build and deployment

## Pull Request Process

### Before Submitting

1. **Ensure tests pass**:
   ```bash
   dotnet test
   ```

2. **Check code formatting**:
   ```bash
   dotnet format
   ```

3. **Run security analysis**:
   ```bash
   dotnet build --verbosity normal
   ```

4. **Update documentation** if needed

### PR Template

When creating a pull request, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that breaks existing functionality)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Performance tests added/updated (if applicable)
- [ ] Manual testing completed

## Checklist
- [ ] Code follows the style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings introduced
```

### Review Process

1. **Automated checks** must pass
2. **Code review** by maintainers
3. **Testing verification**
4. **Documentation review**
5. **Final approval** and merge

### Merge Strategy

- **Squash and merge** for feature branches
- **Merge commit** for release branches
- **Rebase and merge** for small fixes

## Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Describe the bug**
A clear description of the bug

**To Reproduce**
Steps to reproduce the behavior:
1. Configure with '...'
2. Send request '...'
3. See error

**Expected behavior**
What you expected to happen

**Environment:**
- .NET Version: [e.g. 9.0]
- OS: [e.g. Windows 11, Ubuntu 22.04]
- Framework Version: [e.g. 1.2.3]

**Additional context**
Logs, screenshots, etc.
```

### Feature Requests

Use the feature request template:

```markdown
**Is your feature request related to a problem?**
Description of the problem

**Describe the solution you'd like**
Clear description of desired functionality

**Describe alternatives you've considered**
Alternative solutions or features

**Additional context**
Any other context about the feature request
```

## Security Vulnerabilities

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:

1. **Email**: security@[project-domain].com
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

### Security Response

We will:

1. **Acknowledge** receipt within 48 hours
2. **Investigate** and confirm the issue
3. **Develop** a fix
4. **Release** a security update
5. **Publish** a security advisory

### Security Guidelines for Contributors

- **Never commit** secrets or credentials
- **Validate all inputs** thoroughly
- **Use parameterized queries** for database access
- **Implement proper authentication** and authorization
- **Follow secure coding practices**

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project.

### Contributor License Agreement

All contributors must agree to the Contributor License Agreement (CLA) before their contributions can be accepted.

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Documentation**: Comprehensive guides and API reference

### Maintainer Contact

For questions about contributing:

- **GitHub**: @[maintainer-username]
- **Email**: maintainer@[project-domain].com

### Community Guidelines

- **Be patient**: Maintainers are volunteers
- **Be specific**: Provide detailed information in issues
- **Be respectful**: Follow the code of conduct
- **Be helpful**: Help other contributors when possible

---

Thank you for contributing to the Security Framework! Your efforts help make web applications more secure for everyone.