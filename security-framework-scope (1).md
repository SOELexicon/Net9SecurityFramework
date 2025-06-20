# .NET 9 Intelligent Security Framework - Project Scope

## Executive Summary

A comprehensive security framework for .NET 9 applications that provides intelligent IP-based threat detection, behavioral analysis, parameter jacking prevention, and adaptive security responses using machine learning-inspired scoring algorithms with EF Core in-memory database storage. Features optional real-time monitoring capabilities through SignalR/WebSocket integration.

## Core Objectives

1. **Intelligent IP Reputation System**: Track and score IP addresses based on historical behavior
2. **Real-time Threat Detection**: Identify malicious patterns and suspicious activities
3. **Parameter Jacking Prevention**: Detect and block unauthorized access attempts through parameter manipulation
4. **Adaptive Security Response**: Dynamically adjust security measures based on threat levels
5. **High Performance**: Use in-memory storage for sub-millisecond response times
6. **Easy Integration**: Simple API for .NET 9 applications
7. **Optional Real-time Monitoring**: SignalR/WebSocket support that can be enabled/disabled as needed

## Architecture Overview

### Technology Stack
- **.NET 9**: Core framework
- **EF Core 9**: In-memory database provider
- **SQLite**: Persistent storage for in-memory cache
- **ASP.NET Core**: Middleware integration
- **SignalR**: Real-time communications
- **WebSockets**: Low-level real-time support
- **ML.NET**: Optional machine learning for advanced scoring
- **Redis**: Optional distributed cache and SignalR backplane

### Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Application Layer                      │
├─────────────────────────────────────────────────────────┤
│   Security Middleware    │    SignalR/WebSocket Hub     │
├─────────────────┬────────┴──────┬──────────────────────┤
│   Scoring       │   Analysis     │    Response         │
│   Engine        │   Engine       │    Engine           │
├─────────────────┴───────────────┴──────────────────────┤
│              Real-time Event Processor                   │
├─────────────────────────────────────────────────────────┤
│                  Data Access Layer                       │
│              (EF Core In-Memory DB)                      │
└─────────────────────────────────────────────────────────┘
```

## Database Schema (EF Core Models)

### Core Entities

```csharp
public class IPRecord
{
    public string IPAddress { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int TotalRequests { get; set; }
    public double TrustScore { get; set; }
    public double ThreatScore { get; set; }
    public bool IsBlocked { get; set; }
    public string? BlockReason { get; set; }
    public List<IPActivity> Activities { get; set; }
    public List<SecurityIncident> Incidents { get; set; }
}

public class IPActivity
{
    public Guid Id { get; set; }
    public string IPAddress { get; set; }
    public DateTime Timestamp { get; set; }
    public string RequestPath { get; set; }
    public string HttpMethod { get; set; }
    public int StatusCode { get; set; }
    public string UserAgent { get; set; }
    public Dictionary<string, object> Metadata { get; set; }
}

public class SecurityIncident
{
    public Guid Id { get; set; }
    public string IPAddress { get; set; }
    public DateTime IncidentTime { get; set; }
    public IncidentType Type { get; set; }
    public double SeverityScore { get; set; }
    public string Description { get; set; }
    public bool Resolved { get; set; }
}

public class BlocklistEntry
{
    public string IPAddress { get; set; }
    public string Source { get; set; } // Manual, AutoDetected, External
    public DateTime AddedDate { get; set; }
    public DateTime? ExpiryDate { get; set; }
    public string Reason { get; set; }
    public int Priority { get; set; }
}

public class ThreatPattern
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string Pattern { get; set; } // Regex or rule
    public PatternType Type { get; set; }
    public double ThreatMultiplier { get; set; }
    public bool IsActive { get; set; }
    public string Category { get; set; }
    public Dictionary<string, object> Metadata { get; set; }
}

public class PatternTemplate
{
    public string Name { get; set; }
    public string Description { get; set; }
    public List<ThreatPattern> Patterns { get; set; }
    public string Author { get; set; }
    public string Version { get; set; }
    public DateTime LastUpdated { get; set; }
}

public class WebSocketConnection
{
    public string ConnectionId { get; set; }
    public string IPAddress { get; set; }
    public DateTime ConnectedAt { get; set; }
    public string UserIdentifier { get; set; }
    public ConnectionType Type { get; set; } // WebSocket, SignalR
    public Dictionary<string, object> Metadata { get; set; }
    public bool IsAuthenticated { get; set; }
}

public class SecurityNotification
{
    public Guid Id { get; set; }
    public NotificationType Type { get; set; }
    public string Title { get; set; }
    public string Message { get; set; }
    public SeverityLevel Severity { get; set; }
    public DateTime CreatedAt { get; set; }
    public string IPAddress { get; set; }
    public Dictionary<string, object> Data { get; set; }
}

public class ParameterAccess
{
    public Guid Id { get; set; }
    public string IPAddress { get; set; }
    public string UserId { get; set; }
    public DateTime AccessTime { get; set; }
    public string RequestPath { get; set; }
    public string ParameterName { get; set; }
    public string ParameterValue { get; set; }
    public string ExpectedPattern { get; set; }
    public bool IsAuthorized { get; set; }
    public AccessAttemptType Type { get; set; }
}

public class ParameterJackingIncident
{
    public Guid Id { get; set; }
    public string IPAddress { get; set; }
    public string UserId { get; set; }
    public DateTime IncidentTime { get; set; }
    public string AttemptedResource { get; set; }
    public string ActualResource { get; set; }
    public JackingType Type { get; set; } // IDManipulation, PathTraversal, PrivilegeEscalation
    public double SeverityScore { get; set; }
    public string Description { get; set; }
    public bool Blocked { get; set; }
}

public enum JackingType
{
    IDManipulation,      // Changing ID parameters to access other records
    PathTraversal,       // ../../../etc/passwd attempts
    PrivilegeEscalation, // Trying to access admin resources
    SequentialProbing,   // Incrementing IDs systematically
    RandomProbing,       // Random ID attempts
    PatternProbing       // Following discovered patterns
}
```

## Scoring Algorithm

### Trust Score Calculation

```
TrustScore = BaseScore × TimeMultiplier × FrequencyMultiplier × BehaviorMultiplier

Where:
- BaseScore: 50 (neutral starting point)
- TimeMultiplier: 1 + (DaysSinceFirstSeen / 365)
- FrequencyMultiplier: 1 + log(SuccessfulRequests) / 10
- BehaviorMultiplier: 1 - (Incidents / TotalRequests)
```

### Threat Score Components

1. **Pattern-Based Scoring**
   - PHP file access attempts: +20 points
   - SQL injection patterns: +50 points
   - Directory traversal: +40 points
   - Suspicious user agents: +15 points
   - High request rate: +30 points

2. **Parameter Jacking Scoring**
   - ID manipulation attempt: +35 points
   - Sequential ID scanning: +45 points
   - Path traversal in params: +40 points
   - Unauthorized resource access: +50 points
   - Multiple failed attempts: +10 per attempt
   - Pattern probing: +25 points

3. **Historical Scoring**
   - Previous incidents: +10 per incident
   - Blocklist match: +100 points
   - Geographic anomalies: +25 points
   - Time-based anomalies: +20 points

4. **Reputation Scoring**
   - Known VPN/Proxy: +15 points
   - Tor exit node: +30 points
   - Cloud provider IP: +5 points
   - Residential IP: -10 points

### Final Score Calculation

```
FinalThreatLevel = (ThreatScore - TrustScore) × ContextMultiplier

Risk Levels:
- Low: < 25
- Medium: 25-50
- High: 50-75
- Critical: > 75
```

## Core Features

### 1. IP Intelligence System
- **Historical Tracking**: Complete request history per IP
- **Behavioral Profiling**: Pattern recognition and anomaly detection
- **Trust Building**: Reputation improvement over time
- **Geo-location Analysis**: Country/region-based risk assessment

### 2. Threat Detection Patterns
- **Malicious Patterns**:
  - PHP/ASP file probing
  - SQL injection attempts
  - XSS attempts
  - Directory traversal
  - Bot signatures
  - Brute force attempts
  - Rate limit violations
- **Parameter Jacking Detection**:
  - ID manipulation attempts (changing user_id, record_id)
  - Sequential ID scanning (id=1, id=2, id=3...)
  - Path traversal in parameters
  - Unauthorized resource access attempts
  - Pattern-based probing detection
  - User context validation
- **JSON Pattern Templates**:
  - Load patterns from JSON files
  - Hot-reload capability
  - Version control friendly
  - Community pattern sharing

### 3. Blocklist Management
- **Multiple Sources**:
  - Manual entries
  - Auto-detected threats
  - External threat feeds
  - Community blocklists
- **Flexible Rules**:
  - IP ranges (CIDR)
  - Temporary blocks
  - Permanent blocks
  - Conditional blocks

### 4. Data Persistence
- **SQLite Integration**:
  - Automatic persistence of in-memory data
  - Configurable save intervals
  - Load on startup
  - Backup/restore functionality
- **Hybrid Storage**:
  - Hot data in memory
  - Warm data in SQLite
  - Cold data archival options

### 5. Response Actions
- **Graduated Responses**:
  - Allow (score < 25)
  - Challenge (25-50): CAPTCHA, rate limiting
  - Restrict (50-75): Limited access, monitoring
  - Block (>75): Deny access
- **Custom Actions**:
  - Webhook notifications
  - Logging enhancement
  - Traffic shaping
  - Honeypot redirection

### 6. Analytics & Reporting
- **Real-time Dashboard**
- **Threat Trends**
- **IP Analytics**
- **Performance Metrics**
- **Security Reports**

### 7. Real-time Communications (SignalR/WebSocket) - Optional
- **Feature Toggle**: Can be completely disabled via configuration
- **Live Security Dashboard** (when enabled):
  - Real-time threat visualization
  - Active IP monitoring
  - Live attack maps
  - Performance metrics streaming
- **Instant Notifications** (when enabled):
  - Critical threat alerts
  - Blocklist updates
  - Pattern match notifications
  - Threshold breach alerts
- **WebSocket Security**:
  - Connection authentication
  - IP validation for WebSocket connections
  - Rate limiting per connection
  - Encrypted communications
- **SignalR Hubs** (when enabled):
  - SecurityHub for monitoring
  - AdminHub for management
  - AnalyticsHub for reporting
  - AlertHub for notifications
- **Event Streaming** (when enabled):
  - Live security events
  - IP activity streams
  - Pattern detection events
  - System health updates

## Project Folder Structure

```
SecurityFramework/
├── src/
│   ├── SecurityFramework.Core/
│   │   ├── Abstractions/
│   │   │   ├── ISecurityService.cs
│   │   │   ├── IPatternService.cs
│   │   │   ├── IParameterSecurityService.cs
│   │   │   ├── IIPValidationService.cs
│   │   │   └── ISecurityNotificationService.cs
│   │   ├── Attributes/
│   │   │   ├── SecureParameterAttribute.cs
│   │   │   ├── IPRestrictionAttribute.cs
│   │   │   ├── ThreatPatternAttribute.cs
│   │   │   └── RateLimitAttribute.cs
│   │   ├── Models/
│   │   │   ├── Entities/
│   │   │   │   ├── IPRecord.cs
│   │   │   │   ├── IPActivity.cs
│   │   │   │   ├── SecurityIncident.cs
│   │   │   │   ├── BlocklistEntry.cs
│   │   │   │   ├── ThreatPattern.cs
│   │   │   │   ├── ParameterAccess.cs
│   │   │   │   └── ParameterJackingIncident.cs
│   │   │   ├── DTOs/
│   │   │   │   ├── ThreatAssessment.cs
│   │   │   │   ├── SecurityReport.cs
│   │   │   │   ├── IPDetails.cs
│   │   │   │   └── PatternMatchResult.cs
│   │   │   ├── Configuration/
│   │   │   │   ├── SecurityFrameworkOptions.cs
│   │   │   │   ├── IPSecurityOptions.cs
│   │   │   │   ├── ParameterSecurityOptions.cs
│   │   │   │   └── RealTimeOptions.cs
│   │   │   └── Enums/
│   │   │       ├── ThreatLevel.cs
│   │   │       ├── JackingType.cs
│   │   │       ├── PatternType.cs
│   │   │       └── NotificationType.cs
│   │   ├── Extensions/
│   │   │   ├── ServiceCollectionExtensions.cs
│   │   │   ├── ApplicationBuilderExtensions.cs
│   │   │   └── HttpContextExtensions.cs
│   │   ├── Validators/
│   │   │   ├── IPAddressValidator.cs
│   │   │   ├── PatternValidator.cs
│   │   │   └── ParameterValidator.cs
│   │   └── Constants/
│   │       ├── SecurityConstants.cs
│   │       └── DefaultPatterns.cs
│   │
│   ├── SecurityFramework.Data/
│   │   ├── Context/
│   │   │   ├── SecurityDbContext.cs
│   │   │   └── SecurityDbContextFactory.cs
│   │   ├── Configurations/
│   │   │   ├── IPRecordConfiguration.cs
│   │   │   ├── SecurityIncidentConfiguration.cs
│   │   │   └── ParameterAccessConfiguration.cs
│   │   ├── Repositories/
│   │   │   ├── IPRepository.cs
│   │   │   ├── PatternRepository.cs
│   │   │   ├── IncidentRepository.cs
│   │   │   └── ParameterSecurityRepository.cs
│   │   └── Migrations/
│   │       └── (EF Core migrations)
│   │
│   ├── SecurityFramework.Services/
│   │   ├── Core/
│   │   │   ├── SecurityService.cs
│   │   │   ├── IPValidationService.cs
│   │   │   ├── PatternService.cs
│   │   │   └── ScoringEngine.cs
│   │   ├── Detection/
│   │   │   ├── ThreatDetectionService.cs
│   │   │   ├── ParameterJackingDetector.cs
│   │   │   ├── PatternMatcher.cs
│   │   │   └── AnomalyDetector.cs
│   │   ├── Response/
│   │   │   ├── ResponseEngine.cs
│   │   │   ├── BlockingService.cs
│   │   │   └── NotificationService.cs
│   │   ├── Persistence/
│   │   │   ├── SQLitePersistenceService.cs
│   │   │   ├── BackupService.cs
│   │   │   └── DataArchivalService.cs
│   │   └── Analytics/
│   │       ├── AnalyticsService.cs
│   │       ├── ReportingService.cs
│   │       └── MetricsCollector.cs
│   │
│   ├── SecurityFramework.Middleware/
│   │   ├── IPSecurityMiddleware.cs
│   │   ├── ParameterSecurityMiddleware.cs
│   │   ├── RateLimitingMiddleware.cs
│   │   └── WebSocketSecurityMiddleware.cs
│   │
│   ├── SecurityFramework.RealTime/ (Optional Package)
│   │   ├── Hubs/
│   │   │   ├── SecurityHub.cs
│   │   │   ├── AdminHub.cs
│   │   │   └── AnalyticsHub.cs
│   │   ├── Handlers/
│   │   │   ├── SecurityEventHandler.cs
│   │   │   ├── WebSocketHandler.cs
│   │   │   └── ConnectionManager.cs
│   │   └── Events/
│   │       ├── SecurityEventBroadcaster.cs
│   │       └── EventAggregator.cs
│   │
│   └── SecurityFramework.ML/ (Optional Package)
│       ├── Models/
│       │   ├── ThreatPredictionModel.cs
│       │   └── AnomalyDetectionModel.cs
│       ├── Training/
│       │   ├── ModelTrainer.cs
│       │   └── DataPreprocessor.cs
│       └── Inference/
│           └── ThreatPredictor.cs
│
├── tests/
│   ├── SecurityFramework.Core.Tests/
│   ├── SecurityFramework.Services.Tests/
│   ├── SecurityFramework.Integration.Tests/
│   └── SecurityFramework.Performance.Tests/
│
├── samples/
│   ├── BasicWebApi/
│   ├── ECommerceExample/
│   └── EnterpriseDashboard/
│
├── patterns/
│   ├── default/
│   │   ├── owasp-top10.json
│   │   ├── bot-patterns.json
│   │   └── parameter-jacking.json
│   └── community/
│       └── (community-contributed patterns)
│
├── docs/
│   ├── getting-started.md
│   ├── configuration.md
│   ├── patterns.md
│   ├── api-reference.md
│   └── deployment.md
│
├── tools/
│   ├── pattern-validator/
│   └── migration-tools/
│
├── .editorconfig
├── .gitignore
├── Directory.Build.props
├── SecurityFramework.sln
├── README.md
├── LICENSE
└── SECURITY.md
```

## Data Annotations Support

### Core Annotations

```csharp
namespace SecurityFramework.Core.Attributes;

// IP Restriction Attribute
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class IPRestrictionAttribute : Attribute
{
    [Required]
    public string[] AllowedIPs { get; set; }
    
    [Range(0, 100)]
    public int MaxThreatScore { get; set; } = 50;
    
    public bool RequireWhitelist { get; set; }
}

// Secure Parameter Attribute
[AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property)]
public class SecureParameterAttribute : ValidationAttribute
{
    [Required]
    public string ParameterName { get; set; }
    
    public ParameterType Type { get; set; }
    
    [RegularExpression(@"^[a-zA-Z0-9_-]+$")]
    public string Pattern { get; set; }
    
    public bool PreventSequentialAccess { get; set; }
    
    protected override ValidationResult IsValid(object value, ValidationContext context)
    {
        var parameterSecurity = context.GetService<IParameterSecurityService>();
        var httpContext = context.GetService<IHttpContextAccessor>()?.HttpContext;
        
        if (httpContext != null && value != null)
        {
            var isValid = parameterSecurity.ValidateParameterAccessAsync(
                httpContext.User?.Identity?.Name,
                ParameterName,
                value.ToString()
            ).Result;
            
            if (!isValid)
            {
                return new ValidationResult($"Unauthorized access to {ParameterName}");
            }
        }
        
        return ValidationResult.Success;
    }
}

// Rate Limit Attribute
[AttributeUsage(AttributeTargets.Method)]
public class RateLimitAttribute : Attribute
{
    [Required]
    [Range(1, 10000)]
    public int RequestsPerMinute { get; set; }
    
    [Range(1, 1440)]
    public int WindowMinutes { get; set; } = 1;
    
    public string Policy { get; set; } = "Default";
}

// Threat Pattern Attribute
[AttributeUsage(AttributeTargets.Property)]
public class ThreatPatternAttribute : ValidationAttribute
{
    [Required]
    public string PatternName { get; set; }
    
    [Range(0, 100)]
    public double ThreatMultiplier { get; set; } = 1.0;
    
    public PatternType Type { get; set; } = PatternType.Regex;
}
```

### Entity Validation

```csharp
using System.ComponentModel.DataAnnotations;

public class IPRecord
{
    [Key]
    [Required]
    [IPAddress]
    [MaxLength(45)] // Support IPv6
    public string IPAddress { get; set; }
    
    [Required]
    public DateTime FirstSeen { get; set; }
    
    [Required]
    public DateTime LastSeen { get; set; }
    
    [Range(0, int.MaxValue)]
    public int TotalRequests { get; set; }
    
    [Range(0, 100)]
    public double TrustScore { get; set; } = 50.0;
    
    [Range(0, 100)]
    public double ThreatScore { get; set; } = 0.0;
    
    public bool IsBlocked { get; set; }
    
    [MaxLength(500)]
    public string BlockReason { get; set; }
    
    public List<IPActivity> Activities { get; set; }
}

public class ThreatPattern
{
    [Key]
    public Guid Id { get; set; }
    
    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Name { get; set; }
    
    [Required]
    [RegularExpression(@"^.+$", ErrorMessage = "Pattern cannot be empty")]
    public string Pattern { get; set; }
    
    [Required]
    [EnumDataType(typeof(PatternType))]
    public PatternType Type { get; set; }
    
    [Range(0.1, 100)]
    public double ThreatMultiplier { get; set; } = 1.0;
    
    public bool IsActive { get; set; } = true;
    
    [Required]
    [StringLength(50)]
    public string Category { get; set; }
    
    [Required]
    public Dictionary<string, object> Metadata { get; set; }
}

public class ParameterJackingIncident
{
    [Key]
    public Guid Id { get; set; }
    
    [Required]
    [IPAddress]
    public string IPAddress { get; set; }
    
    [StringLength(100)]
    public string UserId { get; set; }
    
    [Required]
    public DateTime IncidentTime { get; set; }
    
    [Required]
    [StringLength(500)]
    public string AttemptedResource { get; set; }
    
    [StringLength(500)]
    public string ActualResource { get; set; }
    
    [Required]
    [EnumDataType(typeof(JackingType))]
    public JackingType Type { get; set; }
    
    [Range(0, 100)]
    public double SeverityScore { get; set; }
    
    [Required]
    [StringLength(1000)]
    public string Description { get; set; }
    
    public bool Blocked { get; set; }
}
```

### Configuration Validation

```csharp
public class SecurityFrameworkOptions : IValidatableObject
{
    [Required]
    public bool EnableInMemoryStorage { get; set; } = true;
    
    public bool EnableSQLitePersistence { get; set; }
    
    [Range(0, 100)]
    public double DefaultThreatThreshold { get; set; } = 50;
    
    [Required]
    public IPSecurityOptions IPSecurity { get; set; } = new();
    
    public ParameterSecurityOptions ParameterSecurity { get; set; } = new();
    
    public RealTimeOptions RealTimeMonitoring { get; set; }
    
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (EnableSQLitePersistence && string.IsNullOrEmpty(SQLiteConnectionString))
        {
            yield return new ValidationResult(
                "SQLite connection string is required when persistence is enabled",
                new[] { nameof(SQLiteConnectionString) }
            );
        }
        
        if (RealTimeMonitoring?.Enabled == true)
        {
            if (!RealTimeMonitoring.EnableSignalR && !RealTimeMonitoring.EnableWebSockets)
            {
                yield return new ValidationResult(
                    "At least one real-time transport must be enabled",
                    new[] { nameof(RealTimeMonitoring) }
                );
            }
        }
    }
}

public class ParameterSecurityOptions
{
    public bool EnableParameterJackingDetection { get; set; } = true;
    
    [Range(1, 100)]
    public int SequentialAccessThreshold { get; set; } = 5;
    
    [Required]
    [Range(typeof(TimeSpan), "00:01:00", "24:00:00")]
    public TimeSpan SequentialAccessWindow { get; set; } = TimeSpan.FromMinutes(5);
    
    [Range(0, 100)]
    public double MaxParameterAnomalyScore { get; set; } = 50;
    
    [EmailAddress]
    public string SecurityAlertEmail { get; set; }
}
```

### Controller Usage

```csharp
[ApiController]
[Route("api/[controller]")]
[IPRestriction(AllowedIPs = new[] { "192.168.1.0/24" }, MaxThreatScore = 25)]
public class SecureController : ControllerBase
{
    [HttpGet("{id}")]
    [RateLimit(RequestsPerMinute = 60)]
    public async Task<IActionResult> GetResource(
        [FromRoute]
        [SecureParameter(ParameterName = "id", Type = ParameterType.UserContext)]
        string id)
    {
        // Parameter is automatically validated
        return Ok(await _service.GetResourceAsync(id));
    }
    
    [HttpPost]
    public async Task<IActionResult> CreatePattern(
        [FromBody]
        [Required]
        ThreatPattern pattern)
    {
        // Model validation is automatic
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        return Ok(await _patternService.AddPatternAsync(pattern));
    }
}
```

### Fluent Validation Integration

```csharp
public class ThreatPatternValidator : AbstractValidator<ThreatPattern>
{
    public ThreatPatternValidator()
    {
        RuleFor(x => x.Name)
            .NotEmpty()
            .Length(3, 100)
            .Matches(@"^[a-zA-Z0-9\s_-]+$");
            
        RuleFor(x => x.Pattern)
            .NotEmpty()
            .Must(BeValidRegex).When(x => x.Type == PatternType.Regex)
            .WithMessage("Invalid regex pattern");
            
        RuleFor(x => x.ThreatMultiplier)
            .InclusiveBetween(0.1, 100);
            
        RuleFor(x => x.Category)
            .NotEmpty()
            .Must(BeValidCategory)
            .WithMessage("Invalid pattern category");
    }
    
    private bool BeValidRegex(string pattern)
    {
        try
        {
            var regex = new Regex(pattern);
            return true;
        }
        catch
        {
            return false;
        }
    }
    
    private bool BeValidCategory(string category)
    {
        var validCategories = new[] 
        { 
            "SQLInjection", "XSS", "PathTraversal", 
            "ParameterJacking", "BotDetection" 
        };
        return validCategories.Contains(category);
    }
}
```

## API Design

### Configuration API
```csharp
services.AddSecurityFramework(options =>
{
    options.EnableInMemoryStorage();
    options.EnableSQLitePersistence("security.db", persistenceOptions =>
    {
        persistenceOptions.AutoSaveInterval = TimeSpan.FromMinutes(5);
        persistenceOptions.EnableCompression = true;
        persistenceOptions.RetentionDays = 90;
    });
    options.SetThreatThreshold(50);
    options.EnablePatternDetection();
    options.LoadPatternsFromJson("patterns/default.json");
    options.LoadPatternsFromDirectory("patterns/custom/");
    options.AddBlocklistSource("https://api.threatfeeds.com/ips");
    
    // Optional real-time monitoring
    options.ConfigureRealTimeMonitoring(realtime =>
    {
        realtime.Enabled = true; // Can be disabled entirely
        realtime.EnableSignalR = true; // Optional
        realtime.EnableWebSockets = true; // Optional
        realtime.AuthenticateConnections = true;
        realtime.MaxConnectionsPerIP = 10;
    });
    
    // Parameter jacking detection
    options.ConfigureParameterSecurity(param =>
    {
        param.EnableParameterJackingDetection = true;
        param.TrackParameterPatterns = true;
        param.DetectIDManipulation = true;
        param.DetectPathTraversal = true;
        param.MaxParameterAnomalyScore = 50;
    });
    
    options.ConfigureScoring(scoring =>
    {
        scoring.SetBaseScore(50);
        scoring.AddPattern("*.php", 20);
        scoring.EnableMachineLearning();
    });
});

// SignalR configuration (optional)
if (configuration.GetValue<bool>("Security:EnableRealTime"))
{
    builder.Services.AddSignalR(options =>
    {
        options.EnableDetailedErrors = true;
        options.MaximumReceiveMessageSize = 102400;
    })
    .AddStackExchangeRedis(connectionString); // For scale-out
}
```

### Runtime API
```csharp
public interface ISecurityService
{
    Task<ThreatAssessment> AssessIPAsync(string ipAddress);
    Task<bool> IsBlockedAsync(string ipAddress);
    Task BlockIPAsync(string ipAddress, string reason, TimeSpan? duration = null);
    Task UnblockIPAsync(string ipAddress);
    Task<IPRecord> GetIPHistoryAsync(string ipAddress);
    Task<SecurityReport> GenerateReportAsync(DateTime from, DateTime to);
    Task ReloadPatternsAsync();
    Task<bool> SaveToSQLiteAsync();
    Task<bool> LoadFromSQLiteAsync();
}

public interface IPatternService
{
    Task LoadPatternsFromJsonAsync(string filePath);
    Task SavePatternsToJsonAsync(string filePath);
    Task<IEnumerable<ThreatPattern>> GetActivePatterns();
    Task AddPatternAsync(ThreatPattern pattern);
    Task RemovePatternAsync(Guid patternId);
    Task<bool> ValidatePattern(string pattern);
}

public interface IParameterSecurityService
{
    Task<bool> ValidateParameterAccessAsync(string userId, string paramName, string paramValue);
    Task<ParameterJackingAssessment> AssessParameterRequestAsync(HttpContext context);
    Task RecordParameterAccessAsync(ParameterAccess access);
    Task<IEnumerable<ParameterJackingIncident>> GetIncidentsByIPAsync(string ipAddress);
    Task<bool> IsParameterPatternSuspiciousAsync(string ipAddress, List<string> recentParams);
}

public interface ISecurityNotificationService
{
    Task SendAlertAsync(SecurityNotification notification);
    Task BroadcastThreatAsync(ThreatDetectedEvent threat);
    Task NotifyIPBlockedAsync(string ipAddress, string reason);
    Task StreamMetricsAsync(SecurityMetrics metrics);
}
```

### SignalR Hub Interfaces
```csharp
public interface ISecurityHub
{
    // Client -> Server methods
    Task Subscribe(string[] eventTypes);
    Task Unsubscribe(string[] eventTypes);
    Task GetCurrentThreats();
    Task GetIPDetails(string ipAddress);
    
    // Server -> Client methods
    Task OnThreatDetected(ThreatInfo threat);
    Task OnIPBlocked(BlockedIPInfo info);
    Task OnPatternMatched(PatternMatchInfo match);
    Task OnMetricsUpdate(MetricsInfo metrics);
}

public class SecurityHub : Hub<ISecurityHubClient>
{
    private readonly ISecurityService _securityService;
    private readonly IConnectionManager _connectionManager;
    
    public override async Task OnConnectedAsync()
    {
        var httpContext = Context.GetHttpContext();
        var clientIP = GetClientIP(httpContext);
        
        // Validate IP for WebSocket connection
        var assessment = await _securityService.AssessIPAsync(clientIP);
        if (assessment.ThreatLevel > ThreatLevel.Medium)
        {
            Context.Abort();
            return;
        }
        
        await _connectionManager.AddConnectionAsync(Context.ConnectionId, clientIP);
        await base.OnConnectedAsync();
    }
    
    public async Task Subscribe(string[] eventTypes)
    {
        foreach (var eventType in eventTypes)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, eventType);
        }
    }
}

public interface IAdminHub
{
    Task UpdatePattern(ThreatPattern pattern);
    Task BlockIP(string ipAddress, string reason);
    Task UnblockIP(string ipAddress);
    Task GetSystemHealth();
    Task ForceDataSync();
}
```

### WebSocket Endpoints
```csharp
app.UseWebSockets(new WebSocketOptions
{
    KeepAliveInterval = TimeSpan.FromSeconds(30),
    AllowedOrigins = { "https://trusted-domain.com" }
});

app.Map("/ws/security", async context =>
{
    if (context.WebSockets.IsWebSocketRequest)
    {
        var clientIP = GetClientIP(context);
        var assessment = await securityService.AssessIPAsync(clientIP);
        
        if (assessment.ThreatLevel <= ThreatLevel.Medium)
        {
            var webSocket = await context.WebSockets.AcceptWebSocketAsync();
            await HandleWebSocketConnection(webSocket, clientIP);
        }
        else
        {
            context.Response.StatusCode = 403;
        }
    }
});

// SignalR endpoints
app.MapHub<SecurityHub>("/hubs/security");
app.MapHub<AdminHub>("/hubs/admin", options =>
{
    options.AuthorizationData.Add(new AuthorizeAttribute { Roles = "Admin" });
});
```

### Event System
```csharp
public interface ISecurityEventHandler
{
    Task OnThreatDetected(ThreatDetectedEvent evt);
    Task OnIPBlocked(IPBlockedEvent evt);
    Task OnPatternMatched(PatternMatchedEvent evt);
    Task OnAnomalyDetected(AnomalyDetectedEvent evt);
}

// Real-time event broadcasting
public class SecurityEventBroadcaster : ISecurityEventHandler
{
    private readonly IHubContext<SecurityHub> _hubContext;
    
    public async Task OnThreatDetected(ThreatDetectedEvent evt)
    {
        // Broadcast to all connected clients in "threats" group
        await _hubContext.Clients.Group("threats")
            .SendAsync("ThreatDetected", new
            {
                evt.IPAddress,
                evt.ThreatLevel,
                evt.Description,
                evt.Timestamp
            });
            
        // Send to specific admin connections
        await _hubContext.Clients.Group("admins")
            .SendAsync("CriticalAlert", evt);
    }
}

// WebSocket event streaming
public class WebSocketEventStream
{
    public async Task StreamEventsAsync(WebSocket webSocket, string clientIP)
    {
        var buffer = new ArraySegment<byte>(new byte[4096]);
        
        while (webSocket.State == WebSocketState.Open)
        {
            var securityEvent = await GetNextSecurityEventAsync();
            var json = JsonSerializer.Serialize(securityEvent);
            var bytes = Encoding.UTF8.GetBytes(json);
            
            await webSocket.SendAsync(
                new ArraySegment<byte>(bytes),
                WebSocketMessageType.Text,
                true,
                CancellationToken.None
            );
        }
    }
}
```

## Performance Specifications

### Target Metrics
- **Latency**: < 1ms for IP assessment (in-memory)
- **SQLite Write**: < 10ms for batch persistence
- **SQLite Read**: < 5ms for startup load
- **Throughput**: 100,000+ requests/second
- **Memory**: < 500MB for 1M IP records
- **SQLite Size**: ~100MB per 1M records (with compression)
- **Startup Time**: < 5 seconds (with SQLite load)
- **WebSocket Connections**: 10,000+ concurrent
- **SignalR Clients**: 50,000+ with Redis backplane
- **Event Broadcast**: < 50ms to all connected clients
- **Real-time Latency**: < 100ms end-to-end

### Optimization Strategies
- In-memory caching with SQLite backing
- Bloom filters for blocklist
- Async processing
- Batch operations for SQLite writes
- Connection pooling
- WAL mode for concurrent access
- Periodic vacuum operations
- WebSocket frame batching
- SignalR message compression
- Redis pub/sub for distributed events

## Security Considerations

### Data Protection
- IP address hashing options
- GDPR compliance features
- Data retention policies
- Audit logging

### Framework Security
- Input validation
- Rate limiting on API
- Authentication for management
- Encrypted storage options

## Integration Points

### Middleware Integration
```csharp
// Basic integration (without real-time features)
app.UseSecurityFramework();
app.UseAuthentication();
app.UseAuthorization();

// Full integration (with optional real-time features)
var securityConfig = app.Services.GetRequiredService<IOptions<SecurityFrameworkOptions>>();

if (securityConfig.Value.RealTimeMonitoring?.Enabled == true)
{
    app.UseWebSockets();
    
    // Map SignalR hubs if enabled
    if (securityConfig.Value.RealTimeMonitoring.EnableSignalR)
    {
        app.MapHub<SecurityHub>("/hubs/security");
        app.MapHub<AdminHub>("/hubs/admin").RequireAuthorization("AdminPolicy");
        app.MapHub<AnalyticsHub>("/hubs/analytics");
    }
    
    // Map WebSocket endpoints if enabled
    if (securityConfig.Value.RealTimeMonitoring.EnableWebSockets)
    {
        app.MapWebSocketManager("/ws/events", serviceProvider.GetService<SecurityEventHandler>());
    }
}
```

### Service Integration
- **Logging**: Serilog, NLog, etc.
- **Monitoring**: Application Insights, Prometheus
- **Caching**: Redis (also as SignalR backplane if real-time enabled)
- **Messaging**: RabbitMQ, Azure Service Bus
- **Real-time**: SignalR with Redis backplane for scale-out (optional)

## JSON Pattern Templates

### Template Structure
```json
{
  "name": "OWASP Top 10 Patterns",
  "description": "Common web application attack patterns",
  "version": "1.0.0",
  "author": "Security Team",
  "lastUpdated": "2024-01-15",
  "patterns": [
    {
      "name": "PHP File Access",
      "pattern": ".*\\.(php|phtml|php3|php4|php5|phps)$",
      "type": "Regex",
      "category": "FileProbing",
      "threatMultiplier": 20,
      "isActive": true,
      "metadata": {
        "severity": "medium",
        "description": "Attempts to access PHP files",
        "mitigation": "Block if no PHP apps are hosted"
      }
    },
    {
      "name": "SQL Injection Basic",
      "pattern": "(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set)",
      "type": "Regex",
      "category": "SQLInjection",
      "threatMultiplier": 50,
      "isActive": true,
      "metadata": {
        "severity": "high",
        "description": "Basic SQL injection patterns",
        "references": ["CWE-89"]
      }
    },
    {
      "name": "Directory Traversal",
      "pattern": "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f)",
      "type": "Regex",
      "category": "PathTraversal",
      "threatMultiplier": 40,
      "isActive": true,
      "metadata": {
        "severity": "high",
        "description": "Path traversal attempts"
      }
    }
  ]
}
```

### Pattern Loading Examples
```csharp
// Load single template
await patternService.LoadPatternsFromJsonAsync("patterns/owasp-top10.json");

// Load all templates from directory
await patternService.LoadPatternsFromDirectoryAsync("patterns/", "*.json");

// Runtime pattern management
await patternService.AddPatternAsync(new ThreatPattern
{
    Name = "Custom Bot Pattern",
    Pattern = "bot|crawler|spider",
    Type = PatternType.Regex,
    ThreatMultiplier = 10
});
```

## Parameter Jacking Detection

### Overview
Parameter jacking (also known as Insecure Direct Object Reference - IDOR) occurs when attackers manipulate parameters to access resources they shouldn't have access to. The framework detects various types of parameter manipulation attempts.

### Detection Patterns

```csharp
// Example: Detecting ID manipulation
public class ParameterJackingMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var userId = context.User?.Identity?.Name;
        var requestedUserId = context.Request.Query["user_id"].ToString();
        
        // Check if user is trying to access another user's data
        if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(requestedUserId))
        {
            if (userId != requestedUserId)
            {
                var assessment = await _parameterSecurity.AssessParameterRequestAsync(context);
                
                if (assessment.ThreatLevel > ThreatLevel.Low)
                {
                    // Log the attempt
                    await _parameterSecurity.RecordParameterAccessAsync(new ParameterAccess
                    {
                        IPAddress = GetClientIP(context),
                        UserId = userId,
                        ParameterName = "user_id",
                        ParameterValue = requestedUserId,
                        IsAuthorized = false,
                        Type = AccessAttemptType.IDManipulation
                    });
                    
                    // Increase threat score
                    await _securityService.IncreaseThreatScoreAsync(
                        GetClientIP(context), 
                        35, 
                        "Parameter jacking attempt"
                    );
                    
                    // Optionally notify in real-time
                    if (_realtimeConfig.Enabled)
                    {
                        await _hubContext.Clients.Group("security")
                            .SendAsync("ParameterJackingDetected", new
                            {
                                IP = GetClientIP(context),
                                User = userId,
                                AttemptedAccess = requestedUserId,
                                Timestamp = DateTime.UtcNow
                            });
                    }
                    
                    context.Response.StatusCode = 403;
                    return;
                }
            }
        }
        
        await next(context);
    }
}
```

### Detection Strategies

1. **Sequential ID Detection**
   ```csharp
   // Detect sequential scanning (id=1, id=2, id=3...)
   public async Task<bool> IsSequentialScanningAsync(string ipAddress, List<int> accessedIds)
   {
       if (accessedIds.Count < 3) return false;
       
       var sorted = accessedIds.OrderBy(x => x).ToList();
       var isSequential = true;
       
       for (int i = 1; i < sorted.Count; i++)
       {
           if (sorted[i] - sorted[i-1] != 1)
           {
               isSequential = false;
               break;
           }
       }
       
       return isSequential && accessedIds.Count > 5;
   }
   ```

2. **Pattern-Based Detection**
   ```json
   {
     "name": "Parameter Jacking Patterns",
     "patterns": [
       {
         "name": "Admin ID Access",
         "pattern": "(admin_id|administrator_id|root_id)",
         "type": "Regex",
         "category": "ParameterJacking",
         "threatMultiplier": 50
       },
       {
         "name": "UUID Manipulation",
         "pattern": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
         "type": "Regex",
         "category": "ParameterJacking",
         "threatMultiplier": 25
       }
     ]
   }
   ```

3. **Context-Aware Validation**
   ```csharp
   public class ContextAwareParameterValidator
   {
       public async Task<bool> ValidateAccessAsync(ClaimsPrincipal user, string resource)
       {
           // Check user's actual permissions
           var userPermissions = await _permissionService.GetUserPermissionsAsync(user);
           var resourceOwner = await _resourceService.GetOwnerAsync(resource);
           
           // Validate ownership or explicit permission
           return user.Identity.Name == resourceOwner || 
                  userPermissions.Contains($"access:{resource}");
       }
   }
   ```

### Configuration Examples

```csharp
// Configure parameter security
services.AddSecurityFramework(options =>
{
    options.ConfigureParameterSecurity(param =>
    {
        param.EnableParameterJackingDetection = true;
        param.TrackParameterPatterns = true;
        param.DetectIDManipulation = true;
        param.DetectPathTraversal = true;
        param.MaxParameterAnomalyScore = 50;
        
        // Define protected parameter patterns
        param.AddProtectedPattern("user_id", ParameterType.UserContext);
        param.AddProtectedPattern("order_id", ParameterType.UserContext);
        param.AddProtectedPattern("account_id", ParameterType.UserContext);
        param.AddProtectedPattern("file_path", ParameterType.PathValidation);
        
        // Sequential access thresholds
        param.SequentialAccessThreshold = 5; // Flag after 5 sequential IDs
        param.SequentialAccessWindow = TimeSpan.FromMinutes(5);
        
        // Auto-block settings
        param.AutoBlockOnHighThreat = true;
        param.BlockDuration = TimeSpan.FromHours(24);
    });
});
```

## SQLite Persistence

### Database Schema
```sql
-- Main security database schema
CREATE TABLE IF NOT EXISTS ip_records (
    ip_address TEXT PRIMARY KEY,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    total_requests INTEGER DEFAULT 0,
    trust_score REAL DEFAULT 50.0,
    threat_score REAL DEFAULT 0.0,
    is_blocked BOOLEAN DEFAULT 0,
    block_reason TEXT,
    metadata TEXT -- JSON serialized data
);

CREATE TABLE IF NOT EXISTS ip_activities (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    request_path TEXT,
    http_method TEXT,
    status_code INTEGER,
    user_agent TEXT,
    metadata TEXT, -- JSON serialized data
    FOREIGN KEY (ip_address) REFERENCES ip_records(ip_address)
);

CREATE TABLE IF NOT EXISTS security_incidents (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    incident_time DATETIME NOT NULL,
    incident_type TEXT NOT NULL,
    severity_score REAL,
    description TEXT,
    resolved BOOLEAN DEFAULT 0,
    FOREIGN KEY (ip_address) REFERENCES ip_records(ip_address)
);

CREATE TABLE IF NOT EXISTS blocklist_entries (
    ip_address TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    added_date DATETIME NOT NULL,
    expiry_date DATETIME,
    reason TEXT,
    priority INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS threat_patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    pattern_type TEXT NOT NULL,
    category TEXT,
    threat_multiplier REAL DEFAULT 1.0,
    is_active BOOLEAN DEFAULT 1,
    metadata TEXT -- JSON serialized data
);

CREATE TABLE IF NOT EXISTS parameter_access (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    user_id TEXT,
    access_time DATETIME NOT NULL,
    request_path TEXT,
    parameter_name TEXT NOT NULL,
    parameter_value TEXT NOT NULL,
    expected_pattern TEXT,
    is_authorized BOOLEAN DEFAULT 0,
    access_type TEXT NOT NULL,
    FOREIGN KEY (ip_address) REFERENCES ip_records(ip_address)
);

CREATE TABLE IF NOT EXISTS parameter_jacking_incidents (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    user_id TEXT,
    incident_time DATETIME NOT NULL,
    attempted_resource TEXT NOT NULL,
    actual_resource TEXT,
    jacking_type TEXT NOT NULL,
    severity_score REAL,
    description TEXT,
    blocked BOOLEAN DEFAULT 0,
    FOREIGN KEY (ip_address) REFERENCES ip_records(ip_address)
);

-- Indexes for performance
CREATE INDEX idx_ip_activities_timestamp ON ip_activities(timestamp);
CREATE INDEX idx_ip_activities_ip ON ip_activities(ip_address);
CREATE INDEX idx_incidents_time ON security_incidents(incident_time);
CREATE INDEX idx_blocklist_expiry ON blocklist_entries(expiry_date);
CREATE INDEX idx_param_access_ip ON parameter_access(ip_address);
CREATE INDEX idx_param_access_time ON parameter_access(access_time);
CREATE INDEX idx_param_jacking_ip ON parameter_jacking_incidents(ip_address);
CREATE INDEX idx_param_jacking_user ON parameter_jacking_incidents(user_id);
```

### Persistence Configuration
```csharp
public class SQLitePersistenceOptions
{
    public string DatabasePath { get; set; } = "security.db";
    public TimeSpan AutoSaveInterval { get; set; } = TimeSpan.FromMinutes(5);
    public bool EnableCompression { get; set; } = true;
    public int RetentionDays { get; set; } = 90;
    public bool LoadOnStartup { get; set; } = true;
    public bool EnableWAL { get; set; } = true; // Write-Ahead Logging
    public int MaxConcurrentReads { get; set; } = 10;
    public BackupStrategy BackupStrategy { get; set; } = BackupStrategy.Daily;
}
```

### Usage Example
```csharp
// Manual save/load
await securityService.SaveToSQLiteAsync();
await securityService.LoadFromSQLiteAsync();

// Backup management
await persistenceService.CreateBackupAsync("backups/security-backup.db");
await persistenceService.RestoreFromBackupAsync("backups/security-backup.db");

// Data archival
await persistenceService.ArchiveOldDataAsync(DateTime.Now.AddDays(-90));
```

## Security Dashboard Architecture

### Real-time Dashboard Components
```typescript
// TypeScript/React dashboard example
interface SecurityDashboard {
    // Live data feeds
    threatFeed: ThreatEvent[];
    ipAnalytics: IPMetrics;
    patternMatches: PatternMatch[];
    systemHealth: SystemMetrics;
    
    // Interactive features
    ipLookup: (ip: string) => Promise<IPDetails>;
    blockIP: (ip: string, reason: string) => Promise<void>;
    updatePattern: (pattern: ThreatPattern) => Promise<void>;
}

// SignalR connection management
class DashboardConnection {
    private connection: signalR.HubConnection;
    
    async connect(): Promise<void> {
        this.connection = new signalR.HubConnectionBuilder()
            .withUrl("/hubs/security")
            .withAutomaticReconnect()
            .configureLogging(signalR.LogLevel.Information)
            .build();
            
        // Register event handlers
        this.connection.on("ThreatDetected", this.onThreatDetected);
        this.connection.on("MetricsUpdate", this.onMetricsUpdate);
        this.connection.on("PatternMatched", this.onPatternMatched);
        
        await this.connection.start();
    }
}
```

### Dashboard Features
- **Threat Map**: 
  - Real-time geographical threat visualization
  - Heat map of attack origins
  - Attack vector paths
  - Country-based statistics

- **Live Metrics**:
  - Requests per second
  - Average threat score
  - Active threats count
  - Blocked IPs count
  - Pattern match rate

- **Event Stream**:
  - Scrolling feed of security events
  - Filterable by severity
  - Searchable by IP/pattern
  - Exportable logs

- **IP Intelligence Panel**:
  - Detailed IP history
  - Trust/threat score evolution
  - Associated patterns
  - Quick actions (block/allow)

- **Pattern Management**:
  - Active pattern list
  - Hit count statistics
  - Enable/disable patterns
  - Import/export templates

- **System Health**:
  - Memory usage
  - CPU utilization
  - WebSocket connections
  - Database size
  - Cache hit rate

## Real-time Dashboard Features

### Live Security Monitor
```javascript
// Client-side SignalR connection
const connection = new signalR.HubConnectionBuilder()
    .withUrl("/hubs/security")
    .withAutomaticReconnect()
    .build();

// Subscribe to threat events
connection.on("ThreatDetected", (threat) => {
    updateThreatMap(threat);
    showNotification(threat);
    updateMetrics(threat);
});

// Real-time metrics streaming
connection.on("MetricsUpdate", (metrics) => {
    updateDashboard({
        activeThreats: metrics.activeThreats,
        blockedIPs: metrics.blockedIPs,
        requestsPerSecond: metrics.rps,
        avgThreatScore: metrics.avgScore
    });
});
```

### Dashboard Components
- **Live Attack Map**: Geographical visualization of threats
- **Real-time Metrics**: Request rates, threat scores, blocked IPs
- **Activity Feed**: Streaming security events
- **Pattern Match Monitor**: Live pattern detection alerts
- **Connection Monitor**: Active WebSocket/SignalR connections
- **System Health**: CPU, memory, throughput metrics

### WebSocket Security Features
```csharp
public class WebSocketSecurityMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (context.WebSockets.IsWebSocketRequest)
        {
            var clientIP = GetClientIP(context);
            var assessment = await _securityService.AssessIPAsync(clientIP);
            
            // Apply rate limiting
            if (!await _rateLimiter.AllowConnectionAsync(clientIP))
            {
                context.Response.StatusCode = 429; // Too Many Requests
                return;
            }
            
            // Check threat level
            if (assessment.ThreatLevel > ThreatLevel.Medium)
            {
                context.Response.StatusCode = 403;
                await _notificationService.NotifyBlockedWebSocketAsync(clientIP);
                return;
            }
            
            // Track connection
            await _connectionManager.RegisterWebSocketAsync(clientIP, context.Connection.Id);
        }
        
        await next(context);
    }
}
```

### Connection Management
- **Per-IP Connection Limits**: Prevent connection flooding
- **Authentication Integration**: Secure WebSocket handshake
- **Connection Tracking**: Monitor all active connections
- **Automatic Cleanup**: Remove stale connections
- **Bandwidth Throttling**: Prevent resource exhaustion

## Extensibility

### Plugin Architecture
- Custom scoring algorithms
- Additional threat patterns
- External blocklist providers
- Custom response handlers

### Pattern Management
- **Pattern Versioning**: Track pattern changes over time
- **Pattern Testing**: Validate patterns before deployment
- **Pattern Sharing**: Export/import pattern templates
- **Community Patterns**: GitHub repository for shared patterns
- **Auto-Update**: Fetch latest patterns from trusted sources

### Machine Learning Integration
- Anomaly detection models
- Pattern classification
- Predictive threat scoring
- Behavioral clustering

## Configurable Features

The framework is designed with flexibility in mind. All major features can be toggled on/off based on your needs:

### Core Features (Always Available)
- IP tracking and scoring
- In-memory storage with SQLite persistence
- Basic threat detection
- Blocklist management
- Pattern matching

### Optional Features (Toggleable)
```csharp
services.AddSecurityFramework(options =>
{
    // Core features
    options.EnableInMemoryStorage = true;
    options.EnableSQLitePersistence = true;
    
    // Optional features
    options.EnablePatternDetection = true;
    options.EnableParameterJackingDetection = true;
    options.EnableMachineLearning = false;
    options.EnableGeoIPAnalysis = false;
    
    // Real-time features (completely optional)
    options.ConfigureRealTimeMonitoring(realtime =>
    {
        realtime.Enabled = false; // Disable all real-time features
        realtime.EnableSignalR = false;
        realtime.EnableWebSockets = false;
    });
});
```

### Feature Dependencies
- SignalR requires `realtime.Enabled = true`
- WebSockets requires `realtime.Enabled = true`
- Machine Learning requires ML.NET package
- Geo-IP requires MaxMind database
- Redis backplane only needed for distributed SignalR

## Deployment Options

### Single Server
- In-memory database
- Local SQLite persistence
- Standalone operation
- Direct WebSocket connections (if real-time enabled)
- No Redis required

### Distributed
- Redis-backed storage (optional)
- Synchronized blocklists
- Centralized analytics
- Load balancer support
- **SignalR Scale-out** (if real-time enabled):
  - Redis backplane for message distribution
  - Sticky sessions for WebSocket connections
  - Azure SignalR Service option
  - Automatic client reconnection
- **Event Distribution**:
  - Pub/sub for security events
  - Distributed caching
  - Session affinity for WebSockets
  - Cross-server notifications

### Minimal Deployment
```csharp
// Bare minimum configuration - no external dependencies
services.AddSecurityFramework(options =>
{
    options.EnableInMemoryStorage = true;
    options.EnableSQLitePersistence = false; // Even this is optional
    options.ConfigureRealTimeMonitoring(rt => rt.Enabled = false);
});
```

## Development Phases

### Phase 1: Core Framework (Months 1-2)
- Basic IP tracking
- In-memory storage with SQLite persistence
- Simple scoring
- Blocklist support
- JSON pattern loading
- Basic WebSocket support

### Phase 2: Advanced Detection (Months 3-4)
- Pattern matching with templates
- Behavioral analysis
- Graduated responses
- Analytics dashboard
- SQLite optimization
- SignalR integration
- Real-time notifications

### Phase 3: Intelligence Layer (Months 5-6)
- Machine learning integration
- External threat feeds
- Advanced scoring
- Pattern auto-updates
- Distributed SignalR support
- Advanced dashboard features

### Phase 4: Enterprise Features (Months 7-8)
- Multi-tenant support
- Advanced reporting
- API management
- Compliance features
- Pattern marketplace
- Enterprise dashboard
- WebSocket clustering

## Use Case Examples

### Security Operations Center (SOC)
```csharp
// Real-time threat monitoring dashboard
public class SOCDashboard : IHostedService
{
    private readonly IHubContext<SecurityHub> _hubContext;
    
    public async Task MonitorThreatsAsync()
    {
        await _hubContext.Clients.Group("soc-operators")
            .SendAsync("ThreatAlert", new
            {
                Level = "Critical",
                IPAddress = "192.168.1.100",
                Pattern = "SQL Injection Attempt",
                Action = "Blocked",
                Timestamp = DateTime.UtcNow
            });
    }
}
```

### Multi-Tenant SaaS Application
```csharp
// Tenant-specific security notifications
public class TenantSecurityHub : Hub
{
    public async Task JoinTenantGroup(string tenantId)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, $"tenant-{tenantId}");
        await Clients.Caller.SendAsync("JoinedTenant", tenantId);
    }
    
    public async Task GetTenantThreats(string tenantId)
    {
        var threats = await _securityService.GetTenantThreatsAsync(tenantId);
        await Clients.Caller.SendAsync("TenantThreats", threats);
    }
}
```

### E-commerce Platform Protection
```csharp
// Real-time bot detection and response
public class EcommerceSecurityMiddleware
{
    public async Task ProcessRequestAsync(HttpContext context)
    {
        var assessment = await _securityService.AssessIPAsync(clientIP);
        
        if (assessment.IsLikelyBot)
        {
            // Notify admins in real-time
            await _hubContext.Clients.Group("admins")
                .SendAsync("BotDetected", new
                {
                    IP = clientIP,
                    UserAgent = context.Request.Headers["User-Agent"],
                    Path = context.Request.Path,
                    Score = assessment.ThreatScore
                });
                
            // Apply CAPTCHA challenge
            context.Response.Redirect("/challenge");
        }
    }
}
```

### API Gateway Protection
```csharp
// Distributed rate limiting with real-time updates
public class APIGatewayProtection
{
    public async Task<bool> CheckRateLimitAsync(string apiKey, string endpoint)
    {
        var result = await _rateLimiter.CheckAsync(apiKey, endpoint);
        
        if (result.Exceeded)
        {
            // Broadcast rate limit violation (if real-time enabled)
            if (_realtimeConfig.Enabled)
            {
                await _hubContext.Clients.All
                    .SendAsync("RateLimitExceeded", new
                    {
                        ApiKey = HashApiKey(apiKey),
                        Endpoint = endpoint,
                        RequestCount = result.Count,
                        Window = result.Window
                    });
            }
        }
        
        return !result.Exceeded;
    }
}
```

### Parameter Jacking Protection
```csharp
// E-commerce order protection
public class OrderController : ControllerBase
{
    private readonly IParameterSecurityService _paramSecurity;
    
    [HttpGet("orders/{orderId}")]
    public async Task<IActionResult> GetOrder(string orderId)
    {
        var userId = User.Identity.Name;
        
        // Validate parameter access
        var isValid = await _paramSecurity.ValidateParameterAccessAsync(
            userId, 
            "orderId", 
            orderId
        );
        
        if (!isValid)
        {
            // Record the attempt
            await _paramSecurity.RecordParameterAccessAsync(new ParameterAccess
            {
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserId = userId,
                ParameterName = "orderId",
                ParameterValue = orderId,
                RequestPath = "/orders/" + orderId,
                IsAuthorized = false,
                Type = AccessAttemptType.IDManipulation
            });
            
            // Check if this is part of a pattern
            var recentAttempts = await _paramSecurity.GetRecentAttemptsAsync(userId);
            if (recentAttempts.Count > 5)
            {
                // Auto-block for parameter jacking
                await _securityService.BlockIPAsync(
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    "Multiple parameter jacking attempts detected",
                    TimeSpan.FromHours(24)
                );
            }
            
            return Forbid("Access denied");
        }
        
        // Proceed with normal order retrieval
        var order = await _orderService.GetOrderAsync(orderId);
        return Ok(order);
    }
}

// Banking application account protection
public class AccountSecurityMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (context.Request.Path.StartsWithSegments("/api/accounts"))
        {
            var accountId = context.Request.RouteValues["accountId"]?.ToString();
            if (!string.IsNullOrEmpty(accountId))
            {
                // Detect sequential account scanning
                var ip = context.Connection.RemoteIpAddress?.ToString();
                var recentAccesses = await _cache.GetAsync<List<string>>($"account_access:{ip}") ?? new List<string>();
                recentAccesses.Add(accountId);
                
                // Check for sequential pattern
                if (IsSequentialPattern(recentAccesses))
                {
                    await _securityService.RecordIncidentAsync(new ParameterJackingIncident
                    {
                        IPAddress = ip,
                        UserId = context.User?.Identity?.Name,
                        AttemptedResource = accountId,
                        Type = JackingType.SequentialProbing,
                        SeverityScore = 75,
                        Description = "Sequential account ID scanning detected"
                    });
                    
                    context.Response.StatusCode = 403;
                    return;
                }
                
                await _cache.SetAsync($"account_access:{ip}", recentAccesses, TimeSpan.FromMinutes(5));
            }
        }
        
        await next(context);
    }
}
```

## Success Metrics

- **Detection Rate**: 95%+ malicious traffic identified
- **False Positive Rate**: < 0.1%
- **Performance Impact**: < 1% overhead
- **Developer Satisfaction**: 4.5+ stars
- **Security Improvement**: 80%+ reduction in successful attacks
- **Real-time Performance**: < 100ms notification latency
- **WebSocket Reliability**: 99.9% uptime
- **Dashboard Responsiveness**: < 200ms UI updates
- **Concurrent Users**: Support 1000+ dashboard viewers
- **Event Throughput**: 10,000+ events/second

## Logging & Auditing

### Structured Logging
```csharp
public interface ISecurityLogger
{
    void LogThreatDetected(ThreatInfo threat);
    void LogIPBlocked(string ip, string reason);
    void LogParameterJacking(ParameterJackingIncident incident);
    void LogPatternMatch(PatternMatchInfo match);
    void LogConfigurationChange(string setting, object oldValue, object newValue);
}

// Implementation with Serilog
public class SecurityLogger : ISecurityLogger
{
    private readonly ILogger<SecurityLogger> _logger;
    
    public void LogThreatDetected(ThreatInfo threat)
    {
        _logger.LogWarning("Threat detected: {ThreatType} from {IPAddress} with score {Score}",
            threat.Type, threat.IPAddress, threat.Score);
    }
}
```

### Audit Trail
- All security decisions logged with timestamp
- User actions tracked
- Configuration changes audited
- Compliance-ready audit logs (GDPR, SOC2)
- Log retention policies
- Tamper-proof logging option

## Health Checks & Monitoring

### Health Check Endpoints
```csharp
public class SecurityFrameworkHealthCheck : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var checks = new Dictionary<string, object>
        {
            ["memory_cache_size"] = _cache.Count,
            ["active_blocks"] = _blockList.Count,
            ["patterns_loaded"] = _patternService.GetActivePatterns().Count(),
            ["sqlite_connected"] = await _persistence.IsConnectedAsync(),
            ["threat_detection_active"] = _detectionService.IsActive
        };
        
        return HealthCheckResult.Healthy("Security Framework is operational", checks);
    }
}

// Registration
services.AddHealthChecks()
    .AddCheck<SecurityFrameworkHealthCheck>("security_framework")
    .AddCheck("sqlite", new SqliteHealthCheck(connectionString))
    .AddSignalRHub("/hubs/security", "signalr_security");
```

### Observability (OpenTelemetry)
```csharp
services.AddOpenTelemetry()
    .WithMetrics(builder =>
    {
        builder.AddMeter("SecurityFramework")
            .AddPrometheusExporter();
    })
    .WithTracing(builder =>
    {
        builder.AddSource("SecurityFramework")
            .AddJaegerExporter();
    });

// Custom metrics
public class SecurityMetrics
{
    private readonly Counter<int> _threatsDetected;
    private readonly Histogram<double> _threatScores;
    private readonly UpDownCounter<int> _activeBlocks;
    
    public void RecordThreatDetected(string threatType)
    {
        _threatsDetected.Add(1, new("threat.type", threatType));
    }
}
```

## Admin Dashboard & Management UI

### Dashboard Features
- **Real-time Overview**: Active threats, blocked IPs, pattern matches
- **IP Management**: Search, block/unblock, view history
- **Pattern Editor**: Visual pattern creation and testing
- **Analytics Dashboard**: Charts, trends, reports
- **Configuration Manager**: Runtime configuration changes
- **Audit Log Viewer**: Searchable security events
- **User Management**: Admin roles and permissions

### Technology Stack
- **Frontend**: React/Angular/Blazor options
- **API**: RESTful management API
- **Authentication**: Integrated with ASP.NET Core Identity
- **Authorization**: Role-based access control

## API Documentation & Developer Experience

### Swagger/OpenAPI Integration
```csharp
services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Security Framework API",
        Version = "v1",
        Description = "Comprehensive security framework for .NET applications"
    });
    
    // Add security definitions
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });
    
    // Include XML comments
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    c.IncludeXmlComments(xmlPath);
});
```

### Client SDKs
- **NuGet Package**: `SecurityFramework.Client`
- **.NET Client**: Strongly-typed client library
- **JavaScript/TypeScript**: NPM package for frontend integration
- **Python**: For data science integration
- **CLI Tool**: Command-line management tool

## Error Handling & Resilience

### Global Error Handler
```csharp
public class SecurityErrorHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext context,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var response = exception switch
        {
            SecurityException => new { error = "Security violation", code = "SEC001" },
            PatternException => new { error = "Invalid pattern", code = "PAT001" },
            RateLimitException => new { error = "Rate limit exceeded", code = "RATE001" },
            _ => new { error = "Internal security error", code = "SEC999" }
        };
        
        context.Response.StatusCode = GetStatusCode(exception);
        await context.Response.WriteAsJsonAsync(response, cancellationToken);
        return true;
    }
}
```

### Retry Policies (Polly Integration)
```csharp
services.AddHttpClient<IThreatFeedClient>()
    .AddPolicyHandler(HttpPolicyExtensions
        .HandleTransientHttpError()
        .WaitAndRetryAsync(3, retryAttempt => 
            TimeSpan.FromSeconds(Math.Pow(2, retryAttempt))));
```

### Circuit Breaker
```csharp
services.AddSingleton<ICircuitBreaker>(provider =>
    new CircuitBreaker(
        failureThreshold: 5,
        samplingDuration: TimeSpan.FromMinutes(1),
        minimumThroughput: 10,
        durationOfBreak: TimeSpan.FromMinutes(5)
    ));
```

## Advanced Features

### Multi-Tenancy Support
```csharp
public interface ITenantResolver
{
    Task<string> GetTenantIdAsync(HttpContext context);
}

public class SecurityFrameworkTenantOptions
{
    public bool EnableTenantIsolation { get; set; }
    public TenantIsolationLevel IsolationLevel { get; set; }
    public Dictionary<string, TenantConfiguration> TenantConfigs { get; set; }
}

public class TenantConfiguration
{
    [Range(0, 100)]
    public double ThreatThreshold { get; set; }
    
    [Required]
    public List<string> AllowedPatterns { get; set; }
    
    public bool EnableRealTimeMonitoring { get; set; }
}
```

### Feature Flags
```csharp
services.AddFeatureManagement()
    .AddFeatureFilter<SecurityFeatureFilter>();

// Usage
if (await _featureManager.IsEnabledAsync("NewScoringAlgorithm"))
{
    score = await _newScoringEngine.CalculateAsync(ip);
}
```

### Webhook Integration
```csharp
public interface IWebhookService
{
    Task RegisterWebhookAsync(WebhookRegistration registration);
    Task TriggerWebhookAsync(string eventType, object payload);
}

public class WebhookRegistration
{
    [Required]
    [Url]
    public string Url { get; set; }
    
    [Required]
    public string[] Events { get; set; }
    
    public string Secret { get; set; }
    
    public Dictionary<string, string> Headers { get; set; }
}
```

### Performance Optimization

#### Caching Strategy
```csharp
public interface ICacheStrategy
{
    Task<T> GetOrAddAsync<T>(string key, Func<Task<T>> factory, CacheOptions options);
}

public class HybridCacheStrategy : ICacheStrategy
{
    private readonly IMemoryCache _l1Cache;
    private readonly IDistributedCache _l2Cache;
    
    // L1: In-memory cache (fast)
    // L2: Redis cache (distributed)
}
```

#### Database Query Optimization
- Compiled queries for hot paths
- Read replicas for analytics
- Batch operations
- Connection pooling
- Query result caching

## Security Headers Management

```csharp
public class SecurityHeadersMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
        context.Response.Headers.Add("Referrer-Policy", "no-referrer");
        context.Response.Headers.Add("Content-Security-Policy", GetCSP());
        
        if (context.Request.IsHttps)
        {
            context.Response.Headers.Add("Strict-Transport-Security", 
                "max-age=31536000; includeSubDomains");
        }
        
        await next(context);
    }
}
```

## DevOps & Deployment

### Docker Support
```dockerfile
# Dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80 443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["SecurityFramework.Core/SecurityFramework.Core.csproj", "SecurityFramework.Core/"]
RUN dotnet restore "SecurityFramework.Core/SecurityFramework.Core.csproj"
COPY . .
RUN dotnet build "SecurityFramework.Core/SecurityFramework.Core.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "SecurityFramework.Core/SecurityFramework.Core.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SecurityFramework.Core.dll"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-framework
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-framework
  template:
    metadata:
      labels:
        app: security-framework
    spec:
      containers:
      - name: security-framework
        image: security-framework:latest
        ports:
        - containerPort: 80
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        livenessProbe:
          httpGet:
            path: /health
            port: 80
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 80
```

### CI/CD Pipeline (GitHub Actions)
```yaml
name: Security Framework CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup .NET
      uses: actions/setup-dotnet@v3
      with:
        dotnet-version: 9.0.x
    - name: Restore dependencies
      run: dotnet restore
    - name: Build
      run: dotnet build --no-restore
    - name: Test
      run: dotnet test --no-build --verbosity normal --collect:"XPlat Code Coverage"
    - name: Security Scan
      run: |
        dotnet tool install --global security-scan
        security-scan ./src
```

## Compliance & Governance

### GDPR Compliance
- IP address anonymization options
- Right to erasure (delete IP records)
- Data portability (export security data)
- Privacy by design principles
- Configurable retention periods

### Compliance Reports
- SOC 2 Type II ready logging
- PCI DSS compliance features
- HIPAA audit trails
- ISO 27001 alignment

## Performance Benchmarks

### Target Benchmarks
```csharp
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class SecurityBenchmarks
{
    [Benchmark]
    public async Task IPAssessment()
    {
        // Target: < 1ms for 95th percentile
        await _securityService.AssessIPAsync("192.168.1.100");
    }
    
    [Benchmark]
    public async Task PatternMatching()
    {
        // Target: < 5ms for 1000 patterns
        await _patternService.MatchAsync("suspicious/path.php");
    }
    
    [Benchmark]
    public async Task ConcurrentRequests()
    {
        // Target: 100,000 RPS
        var tasks = Enumerable.Range(0, 1000)
            .Select(_ => _securityService.ProcessRequestAsync())
            .ToArray();
        await Task.WhenAll(tasks);
    }
}
```

## Cost Estimation

### Resource Requirements
- **Memory**: 500MB-2GB depending on IP count
- **CPU**: 2-4 cores for typical load
- **Storage**: 100MB per million IP records
- **Network**: Minimal bandwidth requirements

### Pricing Model (If Commercial)
- **Community Edition**: Free, limited features
- **Professional**: $X per server/month
- **Enterprise**: Custom pricing with SLA

## Support & Maintenance

### Documentation
- Comprehensive API documentation
- Video tutorials
- Migration guides
- Best practices guide
- Security playbooks

### Community
- GitHub Discussions
- Stack Overflow tag
- Discord/Slack community
- Regular webinars
- Bug bounty program

## Licensing & Distribution

- **Open Source Core**: MIT License
- **Enterprise Edition**: Commercial license
- **NuGet Package**: Public repository
- **Docker Images**: Official containers
- **Documentation**: Comprehensive guides

## API Versioning

### Version Strategy
```csharp
services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = ApiVersionReader.Combine(
        new QueryStringApiVersionReader("api-version"),
        new HeaderApiVersionReader("X-API-Version"),
        new MediaTypeApiVersionReader("version")
    );
});

services.AddVersionedApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

// Controller versioning
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiVersion("2.0")]
public class SecurityController : ControllerBase
{
    [HttpGet]
    [MapToApiVersion("1.0")]
    public async Task<IActionResult> GetV1() { }
    
    [HttpGet]
    [MapToApiVersion("2.0")]
    public async Task<IActionResult> GetV2() { }
}
```

## Localization & Internationalization

### Multi-Language Support
```csharp
services.AddLocalization(options => options.ResourcesPath = "Resources");

services.Configure<RequestLocalizationOptions>(options =>
{
    var supportedCultures = new[] { "en-US", "es-ES", "fr-FR", "de-DE", "zh-CN" };
    options.SetDefaultCulture(supportedCultures[0])
        .AddSupportedCultures(supportedCultures)
        .AddSupportedUICultures(supportedCultures);
});

// Localized error messages
public class LocalizedMessages
{
    private readonly IStringLocalizer<LocalizedMessages> _localizer;
    
    public string GetThreatDetectedMessage() => 
        _localizer["ThreatDetected", DateTime.Now];
        
    public string GetAccessDeniedMessage() => 
        _localizer["AccessDenied"];
}
```

### Resource Files
```
Resources/
├── LocalizedMessages.en-US.resx
├── LocalizedMessages.es-ES.resx
├── LocalizedMessages.fr-FR.resx
├── LocalizedMessages.de-DE.resx
└── LocalizedMessages.zh-CN.resx
```

## Testing Strategy

### Test Categories
1. **Unit Tests**: Core logic, services, validators
2. **Integration Tests**: Database, middleware, API endpoints
3. **Performance Tests**: Load testing, benchmarks
4. **Security Tests**: Penetration testing, vulnerability scanning
5. **Chaos Tests**: Failure injection, resilience testing

### Test Infrastructure
```csharp
public class SecurityFrameworkTestBase : IAsyncLifetime
{
    protected TestServer Server { get; private set; }
    protected HttpClient Client { get; private set; }
    protected IServiceProvider Services { get; private set; }
    
    public async Task InitializeAsync()
    {
        var builder = new WebHostBuilder()
            .UseStartup<TestStartup>()
            .ConfigureServices(services =>
            {
                services.AddSecurityFramework(options =>
                {
                    options.EnableInMemoryStorage = true;
                    options.EnableSQLitePersistence = false;
                });
            });
            
        Server = new TestServer(builder);
        Client = Server.CreateClient();
        Services = Server.Services;
    }
}

// Example test
[Fact]
public async Task DetectsParameterJackingAttempt()
{
    // Arrange
    var client = CreateAuthenticatedClient("user123");
    
    // Act
    var response = await client.GetAsync("/api/orders/456"); // User 123 accessing order 456
    
    // Assert
    response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    var incident = await GetLatestIncident();
    incident.Type.Should().Be(JackingType.IDManipulation);
}
```

## Message Queue Integration

### Event Bus Support
```csharp
public interface ISecurityEventBus
{
    Task PublishAsync<T>(T securityEvent) where T : ISecurityEvent;
    Task SubscribeAsync<T>(Func<T, Task> handler) where T : ISecurityEvent;
}

// RabbitMQ implementation
services.AddMassTransit(x =>
{
    x.AddConsumer<ThreatDetectedConsumer>();
    x.AddConsumer<IPBlockedConsumer>();
    
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host("rabbitmq://localhost");
        cfg.ConfigureEndpoints(context);
    });
});

// Azure Service Bus implementation
services.AddMassTransit(x =>
{
    x.UsingAzureServiceBus((context, cfg) =>
    {
        cfg.Host(connectionString);
    });
});
```

## GraphQL Support (Optional)

```csharp
public class SecurityQuery
{
    [UseProjection]
    [UseFiltering]
    [UseSorting]
    public IQueryable<IPRecord> GetIPRecords([Service] IIPRepository repository) =>
        repository.GetAll();
        
    public async Task<ThreatAssessment> AssessIP(
        string ipAddress,
        [Service] ISecurityService securityService) =>
        await securityService.AssessIPAsync(ipAddress);
}

public class SecurityMutation
{
    public async Task<bool> BlockIP(
        string ipAddress,
        string reason,
        [Service] ISecurityService securityService)
    {
        await securityService.BlockIPAsync(ipAddress, reason);
        return true;
    }
}

// Registration
services.AddGraphQLServer()
    .AddQueryType<SecurityQuery>()
    .AddMutationType<SecurityMutation>()
    .AddFiltering()
    .AddSorting()
    .AddProjections();
```

## gRPC Support (Optional)

```protobuf
syntax = "proto3";

service SecurityService {
    rpc AssessIP (IPAssessmentRequest) returns (IPAssessmentResponse);
    rpc BlockIP (BlockIPRequest) returns (BlockIPResponse);
    rpc GetIPHistory (IPHistoryRequest) returns (stream IPActivity);
}

message IPAssessmentRequest {
    string ip_address = 1;
}

message IPAssessmentResponse {
    double threat_score = 1;
    double trust_score = 2;
    bool is_blocked = 3;
}
```

## Rate Limiting Strategies

### Advanced Algorithms
```csharp
public enum RateLimitAlgorithm
{
    FixedWindow,
    SlidingWindow,
    TokenBucket,
    LeakyBucket,
    ConcurrencyLimit
}

public class RateLimitOptions
{
    public RateLimitAlgorithm Algorithm { get; set; } = RateLimitAlgorithm.SlidingWindow;
    public int Capacity { get; set; } = 100;
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
    public int BurstSize { get; set; } = 20;
    public QueueProcessingOrder QueueOrder { get; set; } = QueueProcessingOrder.OldestFirst;
}

// Usage
services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        httpContext => RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: GetClientIP(httpContext),
            factory: partition => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6
            }));
});
```

## CORS Configuration

```csharp
services.AddCors(options =>
{
    options.AddPolicy("SecurityFrameworkPolicy", policy =>
    {
        policy.WithOrigins(configuration.GetSection("Cors:AllowedOrigins").Get<string[]>())
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()
            .WithExposedHeaders("X-Threat-Score", "X-Rate-Limit-Remaining");
    });
});
```

## Migration Tools

### Data Migration
```csharp
public class MigrationService
{
    public async Task MigrateFromV1ToV2Async()
    {
        // Migrate database schema
        await _context.Database.MigrateAsync();
        
        // Transform data
        var oldRecords = await _v1Repository.GetAllAsync();
        var newRecords = oldRecords.Select(TransformRecord);
        await _v2Repository.BulkInsertAsync(newRecords);
        
        // Update patterns
        await MigratePatternsAsync();
    }
}
```

## Final Architecture Summary

The Security Framework provides:
1. **Core Security**: IP tracking, threat detection, parameter jacking prevention
2. **Data Persistence**: In-memory + SQLite with optional Redis
3. **Real-time Features**: Optional SignalR/WebSocket support
4. **Pattern Management**: JSON templates with hot reload
5. **Comprehensive Logging**: Structured logging with audit trails
6. **Health Monitoring**: Health checks and OpenTelemetry
7. **Admin Dashboard**: Full management UI
8. **Developer Experience**: Data annotations, Swagger, client SDKs
9. **Enterprise Features**: Multi-tenancy, webhooks, compliance
10. **Deployment Ready**: Docker, Kubernetes, CI/CD pipelines
11. **Extensible Architecture**: Plugins, custom validators, ML support
12. **Production Grade**: Error handling, retry policies, circuit breakers

This framework is designed to be a complete, production-ready security solution for .NET 9 applications with flexibility to scale from simple applications to enterprise deployments.