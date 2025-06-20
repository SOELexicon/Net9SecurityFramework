# SecurityFramework API Reference

## Overview

This document provides a comprehensive reference for all public APIs, interfaces, and contracts in the SecurityFramework. All interfaces follow async patterns and support dependency injection.

## Core Service Interfaces

### ISecurityService

Main orchestration service for security operations.

```csharp
namespace SecurityFramework.Core.Abstractions;

public interface ISecurityService
{
    /// <summary>
    /// Assesses the threat level of an IP address based on historical data and patterns
    /// </summary>
    /// <param name="ipAddress">IP address to assess</param>
    /// <param name="context">Optional request context for enhanced analysis</param>
    /// <returns>Comprehensive threat assessment</returns>
    Task<ThreatAssessment> AssessIPAsync(string ipAddress, RequestContext? context = null);

    /// <summary>
    /// Checks if an IP address is currently blocked
    /// </summary>
    /// <param name="ipAddress">IP address to check</param>
    /// <returns>True if blocked, false otherwise</returns>
    Task<bool> IsBlockedAsync(string ipAddress);

    /// <summary>
    /// Blocks an IP address with specified reason and optional duration
    /// </summary>
    /// <param name="ipAddress">IP address to block</param>
    /// <param name="reason">Reason for blocking</param>
    /// <param name="duration">Optional block duration (null for permanent)</param>
    /// <param name="source">Source of the block (manual, automatic, etc.)</param>
    /// <returns>Block result with details</returns>
    Task<BlockResult> BlockIPAsync(string ipAddress, string reason, TimeSpan? duration = null, string source = "Manual");

    /// <summary>
    /// Removes a block on an IP address
    /// </summary>
    /// <param name="ipAddress">IP address to unblock</param>
    /// <param name="reason">Reason for unblocking</param>
    /// <returns>Unblock result</returns>
    Task<UnblockResult> UnblockIPAsync(string ipAddress, string reason);

    /// <summary>
    /// Retrieves comprehensive history for an IP address
    /// </summary>
    /// <param name="ipAddress">IP address to query</param>
    /// <param name="options">Optional query options</param>
    /// <returns>IP history and analytics</returns>
    Task<IPHistory> GetIPHistoryAsync(string ipAddress, HistoryQueryOptions? options = null);

    /// <summary>
    /// Records a security incident for tracking and analysis
    /// </summary>
    /// <param name="incident">Security incident details</param>
    /// <returns>Recorded incident with ID</returns>
    Task<SecurityIncident> RecordIncidentAsync(SecurityIncidentRequest incident);

    /// <summary>
    /// Increases threat score for an IP based on suspicious activity
    /// </summary>
    /// <param name="ipAddress">IP address</param>
    /// <param name="scoreIncrease">Points to add to threat score</param>
    /// <param name="reason">Reason for increase</param>
    /// <param name="context">Optional context information</param>
    /// <returns>Updated threat assessment</returns>
    Task<ThreatAssessment> IncreaseThreatScoreAsync(string ipAddress, double scoreIncrease, string reason, object? context = null);

    /// <summary>
    /// Generates comprehensive security report for specified time range
    /// </summary>
    /// <param name="from">Start date</param>
    /// <param name="to">End date</param>
    /// <param name="options">Report generation options</param>
    /// <returns>Detailed security report</returns>
    Task<SecurityReport> GenerateReportAsync(DateTime from, DateTime to, ReportOptions? options = null);

    /// <summary>
    /// Saves current in-memory state to persistent storage
    /// </summary>
    /// <returns>True if successful</returns>
    Task<bool> SaveStateAsync();

    /// <summary>
    /// Loads state from persistent storage
    /// </summary>
    /// <returns>True if successful</returns>
    Task<bool> LoadStateAsync();
}
```

### IPatternService

Manages threat detection patterns and templates.

```csharp
namespace SecurityFramework.Core.Abstractions;

public interface IPatternService
{
    /// <summary>
    /// Loads patterns from JSON template file
    /// </summary>
    /// <param name="filePath">Path to JSON template file</param>
    /// <returns>Number of patterns loaded</returns>
    Task<int> LoadPatternsFromJsonAsync(string filePath);

    /// <summary>
    /// Loads all patterns from directory
    /// </summary>
    /// <param name="directoryPath">Directory containing JSON files</param>
    /// <param name="pattern">File pattern (e.g., "*.json")</param>
    /// <returns>Number of patterns loaded</returns>
    Task<int> LoadPatternsFromDirectoryAsync(string directoryPath, string pattern = "*.json");

    /// <summary>
    /// Saves current patterns to JSON file
    /// </summary>
    /// <param name="filePath">Output file path</param>
    /// <param name="includeInactive">Include inactive patterns</param>
    /// <returns>True if successful</returns>
    Task<bool> SavePatternsToJsonAsync(string filePath, bool includeInactive = false);

    /// <summary>
    /// Gets all active threat patterns
    /// </summary>
    /// <param name="category">Optional category filter</param>
    /// <returns>Collection of active patterns</returns>
    Task<IEnumerable<ThreatPattern>> GetActivePatternsAsync(string? category = null);

    /// <summary>
    /// Adds a new threat pattern
    /// </summary>
    /// <param name="pattern">Pattern to add</param>
    /// <returns>Added pattern with generated ID</returns>
    Task<ThreatPattern> AddPatternAsync(ThreatPattern pattern);

    /// <summary>
    /// Updates an existing pattern
    /// </summary>
    /// <param name="pattern">Pattern to update</param>
    /// <returns>True if successful</returns>
    Task<bool> UpdatePatternAsync(ThreatPattern pattern);

    /// <summary>
    /// Removes a pattern by ID
    /// </summary>
    /// <param name="patternId">Pattern ID to remove</param>
    /// <returns>True if removed</returns>
    Task<bool> RemovePatternAsync(Guid patternId);

    /// <summary>
    /// Validates a pattern for syntax and security
    /// </summary>
    /// <param name="pattern">Pattern to validate</param>
    /// <returns>Validation result with any errors</returns>
    Task<PatternValidationResult> ValidatePatternAsync(ThreatPattern pattern);

    /// <summary>
    /// Tests a pattern against sample data
    /// </summary>
    /// <param name="patternId">Pattern ID to test</param>
    /// <param name="testData">Test data collection</param>
    /// <returns>Test results</returns>
    Task<PatternTestResult> TestPatternAsync(Guid patternId, IEnumerable<string> testData);

    /// <summary>
    /// Matches input against all active patterns
    /// </summary>
    /// <param name="input">Input to match</param>
    /// <param name="context">Optional matching context</param>
    /// <returns>Collection of pattern matches</returns>
    Task<IEnumerable<PatternMatch>> MatchPatternsAsync(string input, MatchContext? context = null);

    /// <summary>
    /// Hot-reloads patterns from configured sources
    /// </summary>
    /// <returns>Number of patterns reloaded</returns>
    Task<int> ReloadPatternsAsync();
}
```

### IParameterSecurityService

Handles parameter jacking (IDOR) detection and prevention.

```csharp
namespace SecurityFramework.Core.Abstractions;

public interface IParameterSecurityService
{
    /// <summary>
    /// Validates if a user has permission to access a specific parameter value
    /// </summary>
    /// <param name="userId">User making the request</param>
    /// <param name="parameterName">Name of the parameter</param>
    /// <param name="parameterValue">Value being accessed</param>
    /// <param name="context">Optional request context</param>
    /// <returns>True if access is authorized</returns>
    Task<bool> ValidateParameterAccessAsync(string? userId, string parameterName, string parameterValue, RequestContext? context = null);

    /// <summary>
    /// Assesses a request for parameter jacking attempts
    /// </summary>
    /// <param name="context">HTTP request context</param>
    /// <returns>Parameter jacking assessment</returns>
    Task<ParameterJackingAssessment> AssessParameterRequestAsync(HttpContext context);

    /// <summary>
    /// Records a parameter access attempt for tracking
    /// </summary>
    /// <param name="access">Parameter access details</param>
    /// <returns>Recorded access with ID</returns>
    Task<ParameterAccess> RecordParameterAccessAsync(ParameterAccess access);

    /// <summary>
    /// Gets recent parameter access attempts by IP
    /// </summary>
    /// <param name="ipAddress">IP address to query</param>
    /// <param name="timeWindow">Time window for recent attempts</param>
    /// <returns>Collection of recent attempts</returns>
    Task<IEnumerable<ParameterAccess>> GetRecentAttemptsAsync(string ipAddress, TimeSpan? timeWindow = null);

    /// <summary>
    /// Gets parameter jacking incidents by IP
    /// </summary>
    /// <param name="ipAddress">IP address to query</param>
    /// <param name="options">Optional query options</param>
    /// <returns>Collection of incidents</returns>
    Task<IEnumerable<ParameterJackingIncident>> GetIncidentsByIPAsync(string ipAddress, IncidentQueryOptions? options = null);

    /// <summary>
    /// Checks if parameter access pattern is suspicious
    /// </summary>
    /// <param name="ipAddress">IP address</param>
    /// <param name="recentParameters">Recent parameter values accessed</param>
    /// <param name="timeWindow">Time window to analyze</param>
    /// <returns>True if pattern appears suspicious</returns>
    Task<bool> IsParameterPatternSuspiciousAsync(string ipAddress, IEnumerable<string> recentParameters, TimeSpan? timeWindow = null);

    /// <summary>
    /// Detects sequential access patterns (e.g., id=1, id=2, id=3)
    /// </summary>
    /// <param name="ipAddress">IP address</param>
    /// <param name="parameterName">Parameter name to analyze</param>
    /// <param name="timeWindow">Time window for analysis</param>
    /// <returns>Sequential pattern detection result</returns>
    Task<SequentialPatternResult> DetectSequentialAccessAsync(string ipAddress, string parameterName, TimeSpan? timeWindow = null);
}
```

### IIPValidationService

IP-based security validation and assessment.

```csharp
namespace SecurityFramework.Core.Abstractions;

public interface IIPValidationService
{
    /// <summary>
    /// Validates IP address format and security
    /// </summary>
    /// <param name="ipAddress">IP address to validate</param>
    /// <returns>Validation result</returns>
    Task<IPValidationResult> ValidateIPAsync(string ipAddress);

    /// <summary>
    /// Checks if IP is in any blocklist
    /// </summary>
    /// <param name="ipAddress">IP address to check</param>
    /// <returns>Blocklist check result</returns>
    Task<BlocklistResult> CheckBlocklistAsync(string ipAddress);

    /// <summary>
    /// Gets geographic information for IP address
    /// </summary>
    /// <param name="ipAddress">IP address to lookup</param>
    /// <returns>Geographic information</returns>
    Task<GeoIPResult> GetGeoLocationAsync(string ipAddress);

    /// <summary>
    /// Determines if IP is from known hosting/cloud provider
    /// </summary>
    /// <param name="ipAddress">IP address to check</param>
    /// <returns>Hosting provider information</returns>
    Task<HostingProviderResult> GetHostingProviderAsync(string ipAddress);

    /// <summary>
    /// Checks if IP is a known Tor exit node
    /// </summary>
    /// <param name="ipAddress">IP address to check</param>
    /// <returns>True if Tor exit node</returns>
    Task<bool> IsTorExitNodeAsync(string ipAddress);

    /// <summary>
    /// Updates IP activity tracking
    /// </summary>
    /// <param name="activity">Activity to record</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> UpdateIPActivityAsync(IPActivity activity);
}
```

### IScoringEngine

Threat scoring calculation engine.

```csharp
namespace SecurityFramework.Core.Abstractions;

public interface IScoringEngine
{
    /// <summary>
    /// Calculates comprehensive threat score for IP
    /// </summary>
    /// <param name="ipAddress">IP address to score</param>
    /// <param name="context">Optional scoring context</param>
    /// <returns>Detailed scoring result</returns>
    Task<ScoringResult> CalculateThreatScoreAsync(string ipAddress, ScoringContext? context = null);

    /// <summary>
    /// Calculates trust score based on historical behavior
    /// </summary>
    /// <param name="ipRecord">IP record with history</param>
    /// <returns>Trust score (0-100)</returns>
    Task<double> CalculateTrustScoreAsync(IPRecord ipRecord);

    /// <summary>
    /// Calculates pattern-based threat score
    /// </summary>
    /// <param name="patternMatches">Matched patterns</param>
    /// <param name="context">Optional context</param>
    /// <returns>Pattern threat score</returns>
    Task<double> CalculatePatternScoreAsync(IEnumerable<PatternMatch> patternMatches, ScoringContext? context = null);

    /// <summary>
    /// Calculates behavioral anomaly score
    /// </summary>
    /// <param name="ipRecord">IP record with behavior history</param>
    /// <param name="currentBehavior">Current behavior to analyze</param>
    /// <returns>Anomaly score</returns>
    Task<double> CalculateAnomalyScoreAsync(IPRecord ipRecord, BehaviorSnapshot currentBehavior);

    /// <summary>
    /// Maps final score to threat level
    /// </summary>
    /// <param name="score">Combined threat score</param>
    /// <returns>Threat level enumeration</returns>
    ThreatLevel MapScoreToThreatLevel(double score);

    /// <summary>
    /// Determines recommended action based on score
    /// </summary>
    /// <param name="score">Threat score</param>
    /// <param name="context">Optional context for decision</param>
    /// <returns>Recommended security action</returns>
    SecurityAction DetermineAction(double score, ActionContext? context = null);
}
```

### ISecurityNotificationService

Security event notification and broadcasting.

```csharp
namespace SecurityFramework.Core.Abstractions;

public interface ISecurityNotificationService
{
    /// <summary>
    /// Sends security alert notification
    /// </summary>
    /// <param name="notification">Notification details</param>
    /// <returns>True if sent successfully</returns>
    Task<bool> SendAlertAsync(SecurityNotification notification);

    /// <summary>
    /// Broadcasts threat detection to all subscribers
    /// </summary>
    /// <param name="threat">Threat information</param>
    /// <returns>Number of subscribers notified</returns>
    Task<int> BroadcastThreatAsync(ThreatDetectedEvent threat);

    /// <summary>
    /// Notifies about IP blocking event
    /// </summary>
    /// <param name="ipAddress">Blocked IP address</param>
    /// <param name="reason">Reason for blocking</param>
    /// <param name="duration">Block duration</param>
    /// <returns>True if notification sent</returns>
    Task<bool> NotifyIPBlockedAsync(string ipAddress, string reason, TimeSpan? duration = null);

    /// <summary>
    /// Streams real-time security metrics
    /// </summary>
    /// <param name="metrics">Current metrics</param>
    /// <returns>True if streamed successfully</returns>
    Task<bool> StreamMetricsAsync(SecurityMetrics metrics);

    /// <summary>
    /// Registers a webhook for security events
    /// </summary>
    /// <param name="webhook">Webhook configuration</param>
    /// <returns>Webhook registration result</returns>
    Task<WebhookRegistrationResult> RegisterWebhookAsync(WebhookConfiguration webhook);

    /// <summary>
    /// Subscribes to specific event types
    /// </summary>
    /// <param name="subscriberId">Subscriber identifier</param>
    /// <param name="eventTypes">Event types to subscribe to</param>
    /// <returns>Subscription result</returns>
    Task<SubscriptionResult> SubscribeToEventsAsync(string subscriberId, IEnumerable<string> eventTypes);
}
```

## Data Models

### Core Entities

#### IPRecord

```csharp
namespace SecurityFramework.Core.Models.Entities;

public class IPRecord
{
    [Key]
    [Required]
    [IPAddress]
    [MaxLength(45)] // Support IPv6
    public string IPAddress { get; set; } = string.Empty;

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
    public string? BlockReason { get; set; }

    public DateTime? BlockedUntil { get; set; }

    [MaxLength(100)]
    public string? BlockSource { get; set; }

    public virtual ICollection<IPActivity> Activities { get; set; } = new List<IPActivity>();
    public virtual ICollection<SecurityIncident> Incidents { get; set; } = new List<SecurityIncident>();
    public virtual ICollection<ParameterAccess> ParameterAccesses { get; set; } = new List<ParameterAccess>();

    // JSON metadata for additional properties
    public Dictionary<string, object> Metadata { get; set; } = new();
}
```

#### ThreatPattern

```csharp
namespace SecurityFramework.Core.Models.Entities;

public class ThreatPattern
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [RegularExpression(@"^.+$", ErrorMessage = "Pattern cannot be empty")]
    public string Pattern { get; set; } = string.Empty;

    [Required]
    [EnumDataType(typeof(PatternType))]
    public PatternType Type { get; set; }

    [Range(0.1, 100)]
    public double ThreatMultiplier { get; set; } = 1.0;

    public bool IsActive { get; set; } = true;

    [Required]
    [StringLength(50)]
    public string Category { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; }

    public DateTime? LastModified { get; set; }

    [StringLength(100)]
    public string? CreatedBy { get; set; }

    public Dictionary<string, object> Metadata { get; set; } = new();

    // Pattern statistics
    public int MatchCount { get; set; }
    public DateTime? LastMatch { get; set; }
}
```

#### SecurityIncident

```csharp
namespace SecurityFramework.Core.Models.Entities;

public class SecurityIncident
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    [IPAddress]
    public string IPAddress { get; set; } = string.Empty;

    [Required]
    public DateTime IncidentTime { get; set; }

    [Required]
    [EnumDataType(typeof(IncidentType))]
    public IncidentType Type { get; set; }

    [Range(0, 100)]
    public double SeverityScore { get; set; }

    [Required]
    [StringLength(1000)]
    public string Description { get; set; } = string.Empty;

    public bool Resolved { get; set; }

    public DateTime? ResolvedAt { get; set; }

    [StringLength(100)]
    public string? ResolvedBy { get; set; }

    [StringLength(500)]
    public string? Resolution { get; set; }

    // Related entities
    public virtual IPRecord IPRecord { get; set; } = null!;
    public virtual ICollection<PatternMatch> PatternMatches { get; set; } = new List<PatternMatch>();

    public Dictionary<string, object> Metadata { get; set; } = new();
}
```

#### ParameterJackingIncident

```csharp
namespace SecurityFramework.Core.Models.Entities;

public class ParameterJackingIncident
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    [IPAddress]
    public string IPAddress { get; set; } = string.Empty;

    [StringLength(100)]
    public string? UserId { get; set; }

    [Required]
    public DateTime IncidentTime { get; set; }

    [Required]
    [StringLength(500)]
    public string AttemptedResource { get; set; } = string.Empty;

    [StringLength(500)]
    public string? ActualResource { get; set; }

    [Required]
    [EnumDataType(typeof(JackingType))]
    public JackingType Type { get; set; }

    [Range(0, 100)]
    public double SeverityScore { get; set; }

    [Required]
    [StringLength(1000)]
    public string Description { get; set; } = string.Empty;

    public bool Blocked { get; set; }

    [StringLength(500)]
    public string? UserAgent { get; set; }

    [StringLength(1000)]
    public string? RequestPath { get; set; }

    public virtual IPRecord IPRecord { get; set; } = null!;

    public Dictionary<string, object> Metadata { get; set; } = new();
}
```

### DTOs and Response Models

#### ThreatAssessment

```csharp
namespace SecurityFramework.Core.Models.DTOs;

public class ThreatAssessment
{
    [Required]
    [IPAddress]
    public string IPAddress { get; set; } = string.Empty;

    [Range(0, 100)]
    public double ThreatScore { get; set; }

    [Range(0, 100)]
    public double TrustScore { get; set; }

    [Required]
    public ThreatLevel ThreatLevel { get; set; }

    [Required]
    public SecurityAction RecommendedAction { get; set; }

    public bool IsBlocked { get; set; }

    public string? BlockReason { get; set; }

    public DateTime? BlockedUntil { get; set; }

    [Required]
    public DateTime AssessmentTime { get; set; }

    public IEnumerable<PatternMatch> PatternMatches { get; set; } = new List<PatternMatch>();
    public IEnumerable<string> RiskFactors { get; set; } = new List<string>();
    public IEnumerable<string> TrustFactors { get; set; } = new List<string>();

    public ScoringBreakdown ScoreBreakdown { get; set; } = new();
    public IPStatistics Statistics { get; set; } = new();

    public Dictionary<string, object> Metadata { get; set; } = new();
}
```

#### PatternMatch

```csharp
namespace SecurityFramework.Core.Models.DTOs;

public class PatternMatch
{
    [Required]
    public Guid PatternId { get; set; }

    [Required]
    public string PatternName { get; set; } = string.Empty;

    [Required]
    public string Category { get; set; } = string.Empty;

    [Required]
    public PatternType Type { get; set; }

    [Range(0.1, 100)]
    public double ThreatMultiplier { get; set; }

    [Required]
    public string MatchedValue { get; set; } = string.Empty;

    public string? MatchedGroups { get; set; }

    [Required]
    public DateTime MatchTime { get; set; }

    public double Confidence { get; set; } = 1.0;

    public Dictionary<string, object> Context { get; set; } = new();
}
```

#### ParameterJackingAssessment

```csharp
namespace SecurityFramework.Core.Models.DTOs;

public class ParameterJackingAssessment
{
    [Required]
    [IPAddress]
    public string IPAddress { get; set; } = string.Empty;

    public string? UserId { get; set; }

    [Required]
    public DateTime AssessmentTime { get; set; }

    [Range(0, 100)]
    public double RiskScore { get; set; }

    [Required]
    public JackingRiskLevel RiskLevel { get; set; }

    public bool ShouldBlock { get; set; }

    public IEnumerable<JackingIndicator> RiskIndicators { get; set; } = new List<JackingIndicator>();
    public IEnumerable<ParameterAnalysis> ParameterAnalyses { get; set; } = new List<ParameterAnalysis>();

    public SequentialAccessPattern? SequentialPattern { get; set; }
    public AccessFrequencyAnalysis FrequencyAnalysis { get; set; } = new();

    public Dictionary<string, object> Metadata { get; set; } = new();
}
```

### Configuration Models

#### SecurityFrameworkOptions

```csharp
namespace SecurityFramework.Core.Models.Configuration;

public class SecurityFrameworkOptions : IValidatableObject
{
    [Required]
    public bool EnableInMemoryStorage { get; set; } = true;

    public bool EnableSQLitePersistence { get; set; } = false;

    [ConnectionString]
    public string? SQLiteConnectionString { get; set; }

    [Range(0, 100)]
    public double DefaultThreatThreshold { get; set; } = 50;

    [Range(1, 10000)]
    public int MaxIPRecords { get; set; } = 1000000;

    [Range(1, 365)]
    public int DataRetentionDays { get; set; } = 90;

    [Required]
    public IPSecurityOptions IPSecurity { get; set; } = new();

    [Required]
    public ParameterSecurityOptions ParameterSecurity { get; set; } = new();

    public PatternOptions Patterns { get; set; } = new();
    public RealTimeOptions? RealTimeMonitoring { get; set; }
    public MLOptions? MachineLearning { get; set; }
    public NotificationOptions Notifications { get; set; } = new();
    public PerformanceOptions Performance { get; set; } = new();

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

        if (MaxIPRecords < 1000)
        {
            yield return new ValidationResult(
                "MaxIPRecords should be at least 1000 for effective operation",
                new[] { nameof(MaxIPRecords) }
            );
        }
    }
}
```

#### ParameterSecurityOptions

```csharp
namespace SecurityFramework.Core.Models.Configuration;

public class ParameterSecurityOptions
{
    public bool EnableParameterJackingDetection { get; set; } = true;

    public bool TrackParameterPatterns { get; set; } = true;

    public bool DetectIDManipulation { get; set; } = true;

    public bool DetectPathTraversal { get; set; } = true;

    public bool DetectSequentialAccess { get; set; } = true;

    [Range(1, 100)]
    public int SequentialAccessThreshold { get; set; } = 5;

    [Required]
    [Range(typeof(TimeSpan), "00:01:00", "24:00:00")]
    public TimeSpan SequentialAccessWindow { get; set; } = TimeSpan.FromMinutes(5);

    [Range(0, 100)]
    public double MaxParameterAnomalyScore { get; set; } = 50;

    public bool AutoBlockOnHighRisk { get; set; } = true;

    [Range(typeof(TimeSpan), "00:01:00", "30.00:00:00")]
    public TimeSpan AutoBlockDuration { get; set; } = TimeSpan.FromHours(24);

    [EmailAddress]
    public string? SecurityAlertEmail { get; set; }

    public ICollection<ProtectedParameter> ProtectedParameters { get; set; } = new List<ProtectedParameter>();
}
```

### Event Models

#### ThreatDetectedEvent

```csharp
namespace SecurityFramework.Core.Models.Events;

public class ThreatDetectedEvent
{
    [Required]
    public Guid EventId { get; set; }

    [Required]
    [IPAddress]
    public string IPAddress { get; set; } = string.Empty;

    [Required]
    public ThreatLevel ThreatLevel { get; set; }

    [Range(0, 100)]
    public double ThreatScore { get; set; }

    [Required]
    public string Description { get; set; } = string.Empty;

    [Required]
    public DateTime Timestamp { get; set; }

    public SecurityAction ActionTaken { get; set; }

    public IEnumerable<PatternMatch> PatternMatches { get; set; } = new List<PatternMatch>();
    public IEnumerable<string> RiskFactors { get; set; } = new List<string>();

    public Dictionary<string, object> Context { get; set; } = new();
}
```

#### IPBlockedEvent

```csharp
namespace SecurityFramework.Core.Models.Events;

public class IPBlockedEvent
{
    [Required]
    public Guid EventId { get; set; }

    [Required]
    [IPAddress]
    public string IPAddress { get; set; } = string.Empty;

    [Required]
    public string Reason { get; set; } = string.Empty;

    [Required]
    public DateTime BlockedAt { get; set; }

    public DateTime? BlockedUntil { get; set; }

    [Required]
    public string Source { get; set; } = string.Empty; // Manual, Automatic, External

    public double ThreatScore { get; set; }

    public string? RequestPath { get; set; }

    public string? UserAgent { get; set; }

    public Dictionary<string, object> Context { get; set; } = new();
}
```

## Enumerations

### Core Enums

```csharp
namespace SecurityFramework.Core.Models.Enums;

public enum ThreatLevel
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

public enum SecurityAction
{
    Allow = 0,
    Monitor = 1,
    Challenge = 2,
    Restrict = 3,
    Block = 4
}

public enum PatternType
{
    Regex = 0,
    Wildcard = 1,
    Exact = 2,
    Contains = 3,
    StartsWith = 4,
    EndsWith = 5
}

public enum JackingType
{
    IDManipulation = 0,
    PathTraversal = 1,
    PrivilegeEscalation = 2,
    SequentialProbing = 3,
    RandomProbing = 4,
    PatternProbing = 5
}

public enum IncidentType
{
    PatternMatch = 0,
    ParameterJacking = 1,
    RateLimitViolation = 2,
    AnomalousAccess = 3,
    BlocklistHit = 4,
    ManualReport = 5
}

public enum JackingRiskLevel
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

public enum AccessAttemptType
{
    Normal = 0,
    IDManipulation = 1,
    SequentialScanning = 2,
    PathTraversal = 3,
    PrivilegeEscalation = 4,
    UnauthorizedAccess = 5
}
```

## Validation Attributes

### Custom Validation Attributes

```csharp
namespace SecurityFramework.Core.Attributes;

/// <summary>
/// Validates IP address format (IPv4 and IPv6)
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Parameter)]
public class IPAddressAttribute : ValidationAttribute
{
    public bool AllowIPv4 { get; set; } = true;
    public bool AllowIPv6 { get; set; } = true;

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null) return ValidationResult.Success;

        var ipString = value.ToString();
        if (string.IsNullOrEmpty(ipString)) return ValidationResult.Success;

        if (System.Net.IPAddress.TryParse(ipString, out var ipAddress))
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && AllowIPv4)
                return ValidationResult.Success;
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && AllowIPv6)
                return ValidationResult.Success;
        }

        return new ValidationResult("Invalid IP address format");
    }
}

/// <summary>
/// Validates connection string format
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public class ConnectionStringAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null) return ValidationResult.Success;

        var connectionString = value.ToString();
        if (string.IsNullOrEmpty(connectionString)) return ValidationResult.Success;

        // Basic validation - should contain key=value pairs
        if (!connectionString.Contains('='))
        {
            return new ValidationResult("Invalid connection string format");
        }

        return ValidationResult.Success;
    }
}
```

## Security Attributes

### Parameter Protection Attributes

```csharp
namespace SecurityFramework.Core.Attributes;

/// <summary>
/// Marks a parameter as requiring security validation
/// </summary>
[AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property)]
public class SecureParameterAttribute : ValidationAttribute
{
    [Required]
    public string ParameterName { get; set; } = string.Empty;

    public ParameterType Type { get; set; } = ParameterType.UserContext;

    [RegularExpression(@"^[a-zA-Z0-9_-]+$")]
    public string? ExpectedPattern { get; set; }

    public bool PreventSequentialAccess { get; set; } = true;

    public bool RequireOwnership { get; set; } = true;

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        var parameterSecurity = validationContext.GetService<IParameterSecurityService>();
        var httpContextAccessor = validationContext.GetService<IHttpContextAccessor>();

        if (parameterSecurity != null && httpContextAccessor?.HttpContext != null && value != null)
        {
            var isValid = parameterSecurity.ValidateParameterAccessAsync(
                httpContextAccessor.HttpContext.User?.Identity?.Name,
                ParameterName,
                value.ToString()!
            ).GetAwaiter().GetResult();

            if (!isValid)
            {
                return new ValidationResult($"Unauthorized access to parameter '{ParameterName}'");
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Applies IP restrictions to controller actions
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class IPRestrictionAttribute : Attribute
{
    [Required]
    public string[] AllowedIPs { get; set; } = Array.Empty<string>();

    [Range(0, 100)]
    public int MaxThreatScore { get; set; } = 50;

    public bool RequireWhitelist { get; set; } = false;

    public string[]? BlockedCountries { get; set; }

    public bool AllowPrivateNetworks { get; set; } = true;
}

/// <summary>
/// Applies rate limiting to controller actions
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public class RateLimitAttribute : Attribute
{
    [Required]
    [Range(1, 10000)]
    public int RequestsPerMinute { get; set; }

    [Range(1, 1440)]
    public int WindowMinutes { get; set; } = 1;

    public string Policy { get; set; } = "Default";

    public bool PerUser { get; set; } = false;

    public string? CustomKey { get; set; }
}
```

## Extension Methods

### Service Registration Extensions

```csharp
namespace SecurityFramework.Core.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds SecurityFramework services to the DI container
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configureOptions">Configuration action</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddSecurityFramework(
        this IServiceCollection services,
        Action<SecurityFrameworkOptions>? configureOptions = null)
    {
        // Register configuration
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        // Register core services
        services.AddScoped<ISecurityService, SecurityService>();
        services.AddScoped<IPatternService, PatternService>();
        services.AddScoped<IParameterSecurityService, ParameterSecurityService>();
        services.AddScoped<IIPValidationService, IPValidationService>();
        services.AddScoped<IScoringEngine, ScoringEngine>();
        services.AddScoped<ISecurityNotificationService, SecurityNotificationService>();

        // Register data services
        services.AddDbContext<SecurityDbContext>();
        services.AddScoped<IIPRepository, IPRepository>();
        services.AddScoped<IPatternRepository, PatternRepository>();
        services.AddScoped<IIncidentRepository, IncidentRepository>();

        // Register health checks
        services.AddHealthChecks()
            .AddCheck<SecurityFrameworkHealthCheck>("security_framework");

        return services;
    }

    /// <summary>
    /// Adds real-time monitoring services
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configureOptions">Real-time configuration</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddSecurityFrameworkRealTime(
        this IServiceCollection services,
        Action<RealTimeOptions>? configureOptions = null)
    {
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        services.AddSignalR();
        services.AddScoped<ISecurityEventBroadcaster, SecurityEventBroadcaster>();
        services.AddScoped<IConnectionManager, ConnectionManager>();

        return services;
    }
}
```

### Application Builder Extensions

```csharp
namespace SecurityFramework.Core.Extensions;

public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds SecurityFramework middleware to the pipeline
    /// </summary>
    /// <param name="app">Application builder</param>
    /// <param name="configureOptions">Optional middleware configuration</param>
    /// <returns>Application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFramework(
        this IApplicationBuilder app,
        Action<SecurityMiddlewareOptions>? configureOptions = null)
    {
        // Configure options if provided
        if (configureOptions != null)
        {
            var options = new SecurityMiddlewareOptions();
            configureOptions(options);
            app.ApplicationServices.Configure<SecurityMiddlewareOptions>(_ => configureOptions(options));
        }

        // Add middleware in correct order
        app.UseMiddleware<IPSecurityMiddleware>();
        app.UseMiddleware<ParameterSecurityMiddleware>();
        app.UseMiddleware<RateLimitingMiddleware>();

        return app;
    }

    /// <summary>
    /// Maps SecurityFramework SignalR hubs
    /// </summary>
    /// <param name="app">Application builder</param>
    /// <returns>Application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFrameworkRealTime(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetService<IOptions<RealTimeOptions>>()?.Value;

        if (options?.Enabled == true)
        {
            if (options.EnableSignalR)
            {
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapHub<SecurityHub>("/hubs/security");
                    endpoints.MapHub<AdminHub>("/hubs/admin").RequireAuthorization("AdminPolicy");
                    endpoints.MapHub<AnalyticsHub>("/hubs/analytics");
                });
            }

            if (options.EnableWebSockets)
            {
                app.UseWebSockets();
                app.UseMiddleware<WebSocketSecurityMiddleware>();
            }
        }

        return app;
    }
}
```

## Error Handling

### Custom Exceptions

```csharp
namespace SecurityFramework.Core.Exceptions;

public class SecurityFrameworkException : Exception
{
    public string ErrorCode { get; }

    public SecurityFrameworkException(string errorCode, string message) : base(message)
    {
        ErrorCode = errorCode;
    }

    public SecurityFrameworkException(string errorCode, string message, Exception innerException) 
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}

public class SecurityValidationException : SecurityFrameworkException
{
    public SecurityValidationException(string message) : base("SEC_VALIDATION", message) { }
}

public class PatternException : SecurityFrameworkException
{
    public PatternException(string message) : base("PATTERN_ERROR", message) { }
}

public class RateLimitException : SecurityFrameworkException
{
    public int RetryAfterSeconds { get; }

    public RateLimitException(string message, int retryAfterSeconds) : base("RATE_LIMIT", message)
    {
        RetryAfterSeconds = retryAfterSeconds;
    }
}
```

---

> **Note**: All interfaces support cancellation tokens where appropriate for async operations. Implementation classes should respect cancellation tokens and implement proper error handling as defined in the Security Guide.