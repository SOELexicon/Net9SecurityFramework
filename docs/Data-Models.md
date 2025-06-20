# SecurityFramework Data Models

## Overview

The SecurityFramework utilizes a comprehensive data model designed for high-performance threat detection and security analytics. This document provides detailed specifications for all entities, their relationships, validation rules, and database schema design.

## Table of Contents

1. [Entity Architecture](#entity-architecture)
2. [Core Security Entities](#core-security-entities)
3. [Pattern Management Entities](#pattern-management-entities)
4. [Behavioral Analysis Entities](#behavioral-analysis-entities)
5. [Configuration Entities](#configuration-entities)
6. [Audit and Logging Entities](#audit-and-logging-entities)
7. [Performance Optimization Entities](#performance-optimization-entities)
8. [Entity Relationships](#entity-relationships)
9. [Database Schema Design](#database-schema-design)
10. [Data Validation Attributes](#data-validation-attributes)
11. [Entity Framework Configuration](#entity-framework-configuration)
12. [Data Access Patterns](#data-access-patterns)
13. [Migration Strategies](#migration-strategies)

## Entity Architecture

### Entity Design Principles

#### 1. Performance-First Design
- **In-Memory Primary Storage**: Critical entities optimized for memory storage
- **Selective Persistence**: Only essential data persisted to SQLite
- **Indexing Strategy**: Strategic indexing for query optimization
- **Denormalization**: Calculated fields for performance

#### 2. Data Integrity
- **Strong Typing**: Comprehensive type safety
- **Validation Attributes**: Multi-layer validation
- **Referential Integrity**: Proper foreign key relationships
- **Immutable Events**: Append-only security events

#### 3. Scalability
- **Partitioning Strategy**: Time-based data partitioning
- **Archival Policies**: Automated data lifecycle management
- **Memory Management**: Efficient memory usage patterns
- **Query Optimization**: Optimized query patterns

### Entity Base Classes

#### BaseEntity
```csharp
public abstract class BaseEntity
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }
    
    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
    
    [MaxLength(100)]
    public string? CreatedBy { get; set; }
    
    [MaxLength(100)]
    public string? UpdatedBy { get; set; }
    
    [Timestamp]
    public byte[] RowVersion { get; set; } = new byte[8];
}
```

#### SecurityEventBase
```csharp
public abstract class SecurityEventBase : BaseEntity
{
    [Required]
    [MaxLength(50)]
    public string EventType { get; set; } = string.Empty;
    
    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    [Required]
    [MaxLength(50)]
    public string Severity { get; set; } = "Info";
    
    [MaxLength(45)]
    [IpAddressValidation]
    public string? ClientIP { get; set; }
    
    [MaxLength(36)]
    public string? RequestId { get; set; }
    
    [MaxLength(36)]
    public string? SessionId { get; set; }
    
    [MaxLength(100)]
    public string? UserId { get; set; }
    
    [MaxLength(1000)]
    public string? UserAgent { get; set; }
    
    public string? AdditionalData { get; set; }
}
```

## Core Security Entities

### IPSecurityRecord
```csharp
[Table("IPSecurityRecords")]
[Index(nameof(IPAddress), IsUnique = true)]
[Index(nameof(LastActivityAt))]
[Index(nameof(ThreatScore))]
public class IPSecurityRecord : BaseEntity
{
    [Required]
    [MaxLength(45)]
    [IpAddressValidation]
    public string IPAddress { get; set; } = string.Empty;
    
    [Range(0, 100)]
    public double ThreatScore { get; set; }
    
    [Range(0, 100)]
    public double TrustScore { get; set; }
    
    [Range(0, int.MaxValue)]
    public int RequestCount { get; set; }
    
    [Range(0, int.MaxValue)]
    public int ThreatIncidents { get; set; }
    
    public DateTime FirstSeenAt { get; set; } = DateTime.UtcNow;
    
    public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? LastThreatAt { get; set; }
    
    public bool IsBlocked { get; set; }
    
    public DateTime? BlockedAt { get; set; }
    
    public DateTime? BlockExpiresAt { get; set; }
    
    [MaxLength(500)]
    public string? BlockReason { get; set; }
    
    [MaxLength(50)]
    public string? BlockSource { get; set; }
    
    // Geographic Information
    [MaxLength(2)]
    public string? CountryCode { get; set; }
    
    [MaxLength(100)]
    public string? CountryName { get; set; }
    
    [MaxLength(100)]
    public string? Region { get; set; }
    
    [MaxLength(100)]
    public string? City { get; set; }
    
    [Range(-90, 90)]
    public double? Latitude { get; set; }
    
    [Range(-180, 180)]
    public double? Longitude { get; set; }
    
    [MaxLength(50)]
    public string? Timezone { get; set; }
    
    [MaxLength(200)]
    public string? ISP { get; set; }
    
    public bool IsProxy { get; set; }
    
    public bool IsTor { get; set; }
    
    public bool IsHosting { get; set; }
    
    // Behavioral Metrics
    public double AverageRequestRate { get; set; }
    
    public TimeSpan AverageSessionDuration { get; set; }
    
    [MaxLength(4000)]
    public string? CommonUserAgents { get; set; } // JSON array
    
    [MaxLength(4000)]
    public string? AccessPatterns { get; set; } // JSON array
    
    // Calculated Fields
    [NotMapped]
    public bool IsTrusted => TrustScore > 70 && ThreatScore < 30;
    
    [NotMapped]
    public bool IsHighRisk => ThreatScore > 80 || ThreatIncidents > 5;
    
    [NotMapped]
    public bool IsActivelyBlocked => IsBlocked && (BlockExpiresAt == null || BlockExpiresAt > DateTime.UtcNow);
    
    // Navigation Properties
    public virtual ICollection<SecurityEvent> SecurityEvents { get; set; } = new List<SecurityEvent>();
    public virtual ICollection<ThreatEvent> ThreatEvents { get; set; } = new List<ThreatEvent>();
    public virtual ICollection<ParameterJackingEvent> ParameterJackingEvents { get; set; } = new List<ParameterJackingEvent>();
}
```

### SecurityEvent
```csharp
[Table("SecurityEvents")]
[Index(nameof(EventType))]
[Index(nameof(Timestamp))]
[Index(nameof(ThreatScore))]
[Index(nameof(ClientIP))]
public class SecurityEvent : SecurityEventBase
{
    [Required]
    [MaxLength(36)]
    public string EventId { get; set; } = Guid.NewGuid().ToString();
    
    [Range(0, 100)]
    public double ThreatScore { get; set; }
    
    [MaxLength(50)]
    public string? ThreatLevel { get; set; }
    
    [MaxLength(50)]
    public string? ActionTaken { get; set; }
    
    [MaxLength(1000)]
    public string? Description { get; set; }
    
    [MaxLength(100)]
    public string? Component { get; set; }
    
    [MaxLength(20)]
    public string? Version { get; set; }
    
    [MaxLength(100)]
    public string? InstanceId { get; set; }
    
    [MaxLength(100)]
    public string? Hostname { get; set; }
    
    // Request Context
    [MaxLength(10)]
    public string? RequestMethod { get; set; }
    
    [MaxLength(2000)]
    public string? RequestUrl { get; set; }
    
    [MaxLength(1000)]
    public string? RequestPath { get; set; }
    
    [MaxLength(2000)]
    public string? QueryString { get; set; }
    
    [MaxLength(100)]
    public string? ContentType { get; set; }
    
    public int? ContentLength { get; set; }
    
    [MaxLength(20)]
    public string? Protocol { get; set; }
    
    public bool? IsEncrypted { get; set; }
    
    [MaxLength(2000)]
    public string? Referrer { get; set; }
    
    // Response Context
    public int? ResponseStatusCode { get; set; }
    
    [MaxLength(100)]
    public string? ResponseContentType { get; set; }
    
    public int? ResponseContentLength { get; set; }
    
    public double? ResponseTime { get; set; }
    
    // Geographic Context (denormalized for performance)
    [MaxLength(2)]
    public string? CountryCode { get; set; }
    
    [MaxLength(100)]
    public string? CountryName { get; set; }
    
    [MaxLength(100)]
    public string? City { get; set; }
    
    // Additional structured data as JSON
    public string? Metadata { get; set; }
    
    [MaxLength(500)]
    public string? Tags { get; set; } // JSON array
    
    // Foreign Keys
    public long? IPSecurityRecordId { get; set; }
    
    // Navigation Properties
    public virtual IPSecurityRecord? IPSecurityRecord { get; set; }
    public virtual ICollection<PatternMatch> PatternMatches { get; set; } = new List<PatternMatch>();
}
```

### ThreatEvent
```csharp
[Table("ThreatEvents")]
[Index(nameof(ThreatType))]
[Index(nameof(ThreatScore))]
[Index(nameof(DetectedAt))]
[Index(nameof(ClientIP))]
public class ThreatEvent : SecurityEventBase
{
    [Required]
    [MaxLength(36)]
    public string ThreatId { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    [MaxLength(50)]
    public string ThreatType { get; set; } = string.Empty;
    
    [Range(0, 100)]
    public double ThreatScore { get; set; }
    
    [Range(0, 100)]
    public double TrustScore { get; set; }
    
    [Range(0, 1)]
    public double Confidence { get; set; }
    
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    
    [MaxLength(50)]
    public string ActionTaken { get; set; } = "Monitor";
    
    [MaxLength(1000)]
    public string? Description { get; set; }
    
    [MaxLength(2000)]
    public string? AttackVector { get; set; }
    
    [MaxLength(1000)]
    public string? MatchedValue { get; set; }
    
    public bool IsBlocked { get; set; }
    
    public bool IsFalsePositive { get; set; }
    
    public DateTime? ResolvedAt { get; set; }
    
    [MaxLength(100)]
    public string? ResolvedBy { get; set; }
    
    [MaxLength(500)]
    public string? ResolutionNotes { get; set; }
    
    // Risk Factors (JSON array)
    public string? RiskFactors { get; set; }
    
    // Score Breakdown (JSON object)
    public string? ScoreBreakdown { get; set; }
    
    // Pattern Matches (JSON array)
    public string? PatternMatches { get; set; }
    
    // Foreign Keys
    public long? IPSecurityRecordId { get; set; }
    
    // Navigation Properties
    public virtual IPSecurityRecord? IPSecurityRecord { get; set; }
}
```

### ParameterJackingEvent
```csharp
[Table("ParameterJackingEvents")]
[Index(nameof(ParameterName))]
[Index(nameof(JackingType))]
[Index(nameof(RiskScore))]
[Index(nameof(DetectedAt))]
public class ParameterJackingEvent : SecurityEventBase
{
    [Required]
    [MaxLength(36)]
    public string JackingId { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    [MaxLength(100)]
    public string ParameterName { get; set; } = string.Empty;
    
    [Required]
    [MaxLength(1000)]
    public string AttemptedValue { get; set; } = string.Empty;
    
    [MaxLength(1000)]
    public string? ExpectedValue { get; set; }
    
    [Required]
    [MaxLength(50)]
    public string JackingType { get; set; } = string.Empty;
    
    [Range(0, 100)]
    public double RiskScore { get; set; }
    
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    
    public bool IsBlocked { get; set; }
    
    [MaxLength(100)]
    public string? AuthorizedUserId { get; set; }
    
    [MaxLength(500)]
    public string? AuthorizedResource { get; set; }
    
    [MaxLength(500)]
    public string? AttemptedResource { get; set; }
    
    [MaxLength(2000)]
    public string? RequestContext { get; set; } // JSON
    
    // Sequential Access Detection
    public bool IsSequentialAccess { get; set; }
    
    public int? SequencePosition { get; set; }
    
    public TimeSpan? TimeSinceLastAccess { get; set; }
    
    // Pattern Information
    [MaxLength(100)]
    public string? DetectionPattern { get; set; }
    
    [Range(0, 1)]
    public double PatternConfidence { get; set; }
    
    // Mitigation
    [MaxLength(50)]
    public string MitigationAction { get; set; } = "Monitor";
    
    public DateTime? MitigatedAt { get; set; }
    
    [MaxLength(100)]
    public string? MitigatedBy { get; set; }
    
    // Foreign Keys
    public long? IPSecurityRecordId { get; set; }
    
    // Navigation Properties
    public virtual IPSecurityRecord? IPSecurityRecord { get; set; }
}
```

## Pattern Management Entities

### ThreatPattern
```csharp
[Table("ThreatPatterns")]
[Index(nameof(Name), IsUnique = true)]
[Index(nameof(Category))]
[Index(nameof(IsActive))]
[Index(nameof(Priority))]
public class ThreatPattern : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    
    [Required]
    [MaxLength(2000)]
    public string Pattern { get; set; } = string.Empty;
    
    [Required]
    [MaxLength(50)]
    public string Type { get; set; } = "Regex";
    
    [Required]
    [MaxLength(50)]
    public string Category { get; set; } = string.Empty;
    
    [Range(0.1, 100)]
    public double ThreatMultiplier { get; set; } = 1.0;
    
    public bool IsActive { get; set; } = true;
    
    [MaxLength(1000)]
    public string? Description { get; set; }
    
    [Range(1, 100)]
    public int Priority { get; set; } = 50;
    
    [Range(0, 1)]
    public double Confidence { get; set; } = 1.0;
    
    [MaxLength(50)]
    public string? Severity { get; set; }
    
    [MaxLength(100)]
    public string? Author { get; set; }
    
    [MaxLength(20)]
    public string? Version { get; set; }
    
    // Conditions (JSON)
    public string? Conditions { get; set; }
    
    // Actions (JSON)
    public string? Actions { get; set; }
    
    // Machine Learning Config (JSON)
    public string? MLConfig { get; set; }
    
    // Metadata (JSON)
    public string? Metadata { get; set; }
    
    // Performance Metrics
    public int MatchCount { get; set; }
    
    public double AverageMatchTime { get; set; }
    
    public DateTime? LastMatchedAt { get; set; }
    
    public int FalsePositiveCount { get; set; }
    
    public int TruePositiveCount { get; set; }
    
    // Compiled Pattern Cache
    [NotMapped]
    public Regex? CompiledPattern { get; set; }
    
    [NotMapped]
    public double Accuracy => TruePositiveCount + FalsePositiveCount > 0 
        ? (double)TruePositiveCount / (TruePositiveCount + FalsePositiveCount) 
        : 0;
    
    // Navigation Properties
    public virtual PatternTemplate? PatternTemplate { get; set; }
    public virtual ICollection<PatternMatch> PatternMatches { get; set; } = new List<PatternMatch>();
    public virtual ICollection<PatternTestCase> TestCases { get; set; } = new List<PatternTestCase>();
}
```

### PatternTemplate
```csharp
[Table("PatternTemplates")]
[Index(nameof(Name), IsUnique = true)]
[Index(nameof(Version))]
[Index(nameof(IsEnabled))]
public class PatternTemplate : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    
    [MaxLength(1000)]
    public string? Description { get; set; }
    
    [Required]
    [MaxLength(20)]
    public string Version { get; set; } = "1.0.0";
    
    [MaxLength(100)]
    public string? Author { get; set; }
    
    [MaxLength(50)]
    public string? License { get; set; }
    
    [MaxLength(500)]
    public string? Homepage { get; set; }
    
    [MaxLength(500)]
    public string? Repository { get; set; }
    
    public DateTime? LastUpdated { get; set; }
    
    public bool IsEnabled { get; set; } = true;
    
    [Range(1, 100)]
    public int Priority { get; set; } = 50;
    
    [Range(0.1, 10)]
    public double GlobalThreatMultiplier { get; set; } = 1.0;
    
    // Tags (JSON array)
    public string? Tags { get; set; }
    
    // Categories (JSON array)
    public string? Categories { get; set; }
    
    // Target Industries (JSON array)
    public string? TargetIndustries { get; set; }
    
    [MaxLength(20)]
    public string? MinimumFrameworkVersion { get; set; }
    
    // Dependencies (JSON array)
    public string? Dependencies { get; set; }
    
    // Configuration (JSON object)
    public string? Configuration { get; set; }
    
    // Metadata (JSON object)
    public string? Metadata { get; set; }
    
    // Performance Statistics
    public int TotalPatterns { get; set; }
    
    public int ActivePatterns { get; set; }
    
    public double AverageThreatScore { get; set; }
    
    public double AverageMatchTime { get; set; }
    
    public int MemoryUsageKB { get; set; }
    
    public double FalsePositiveRate { get; set; }
    
    // Navigation Properties
    public virtual ICollection<ThreatPattern> Patterns { get; set; } = new List<ThreatPattern>();
    public virtual ICollection<PatternGroup> PatternGroups { get; set; } = new List<PatternGroup>();
}
```

### PatternMatch
```csharp
[Table("PatternMatches")]
[Index(nameof(MatchedAt))]
[Index(nameof(PatternName))]
[Index(nameof(ThreatMultiplier))]
public class PatternMatch : BaseEntity
{
    [Required]
    [MaxLength(36)]
    public string MatchId { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    [MaxLength(100)]
    public string PatternName { get; set; } = string.Empty;
    
    [MaxLength(50)]
    public string? PatternCategory { get; set; }
    
    [Required]
    [MaxLength(10000)]
    public string MatchedValue { get; set; } = string.Empty;
    
    [Range(0.1, 100)]
    public double ThreatMultiplier { get; set; }
    
    [Range(0, 1)]
    public double Confidence { get; set; }
    
    [MaxLength(50)]
    public string MatchType { get; set; } = "Exact";
    
    [MaxLength(50)]
    public string? MatchLocation { get; set; }
    
    public DateTime MatchedAt { get; set; } = DateTime.UtcNow;
    
    public double ExecutionTimeMs { get; set; }
    
    [MaxLength(45)]
    public string? ClientIP { get; set; }
    
    [MaxLength(36)]
    public string? RequestId { get; set; }
    
    // Additional Context (JSON)
    public string? Context { get; set; }
    
    // Foreign Keys
    public long? PatternId { get; set; }
    public long? SecurityEventId { get; set; }
    
    // Navigation Properties
    public virtual ThreatPattern? Pattern { get; set; }
    public virtual SecurityEvent? SecurityEvent { get; set; }
}
```

### PatternGroup
```csharp
[Table("PatternGroups")]
[Index(nameof(Name))]
[Index(nameof(Priority))]
public class PatternGroup : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    
    [MaxLength(500)]
    public string? Description { get; set; }
    
    public bool IsEnabled { get; set; } = true;
    
    [Range(1, 100)]
    public int Priority { get; set; } = 50;
    
    // Pattern Names (JSON array)
    [Required]
    public string PatternNames { get; set; } = "[]";
    
    // Conditions (JSON object)
    public string? Conditions { get; set; }
    
    // Foreign Keys
    public long? PatternTemplateId { get; set; }
    
    // Navigation Properties
    public virtual PatternTemplate? PatternTemplate { get; set; }
}
```

### PatternTestCase
```csharp
[Table("PatternTestCases")]
[Index(nameof(PatternId))]
public class PatternTestCase : BaseEntity
{
    [Required]
    [MaxLength(10000)]
    public string Input { get; set; } = string.Empty;
    
    public bool ShouldMatch { get; set; }
    
    [MaxLength(200)]
    public string? Description { get; set; }
    
    // Test Context (JSON)
    public string? Context { get; set; }
    
    [Range(0, 100)]
    public double? ExpectedThreatScore { get; set; }
    
    // Test Results
    public bool? LastTestResult { get; set; }
    
    public DateTime? LastTestedAt { get; set; }
    
    public double? LastExecutionTimeMs { get; set; }
    
    // Foreign Keys
    public long PatternId { get; set; }
    
    // Navigation Properties
    public virtual ThreatPattern Pattern { get; set; } = null!;
}
```

## Behavioral Analysis Entities

### UserBehaviorBaseline
```csharp
[Table("UserBehaviorBaselines")]
[Index(nameof(UserId), IsUnique = true)]
[Index(nameof(LastUpdatedAt))]
public class UserBehaviorBaseline : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string UserId { get; set; } = string.Empty;
    
    public double AverageRequestsPerHour { get; set; }
    
    public double AverageSessionDurationMinutes { get; set; }
    
    public TimeSpan TypicalActiveHourStart { get; set; }
    
    public TimeSpan TypicalActiveHourEnd { get; set; }
    
    [MaxLength(2)]
    public string? PrimaryCountryCode { get; set; }
    
    [MaxLength(100)]
    public string? PrimaryCity { get; set; }
    
    // JSON Arrays
    public string? TypicalEndpoints { get; set; }
    
    public string? CommonUserAgents { get; set; }
    
    public string? EndpointFrequency { get; set; }
    
    public string? ParameterPatterns { get; set; }
    
    public string? GeographicHistory { get; set; }
    
    // Baseline Metrics
    public int TotalSessions { get; set; }
    
    public int TotalRequests { get; set; }
    
    public DateTime FirstActivityAt { get; set; } = DateTime.UtcNow;
    
    public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;
    
    public DateTime LastUpdatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime BaselineExpiresAt { get; set; } = DateTime.UtcNow.AddDays(30);
    
    // Quality Metrics
    [Range(0, 1)]
    public double BaselineConfidence { get; set; }
    
    public int AnomalyCount { get; set; }
    
    public DateTime? LastAnomalyAt { get; set; }
    
    // Navigation Properties
    public virtual ICollection<BehaviorAnomaly> Anomalies { get; set; } = new List<BehaviorAnomaly>();
}
```

### BehaviorAnomaly
```csharp
[Table("BehaviorAnomalies")]
[Index(nameof(UserId))]
[Index(nameof(AnomalyType))]
[Index(nameof(AnomalyScore))]
[Index(nameof(DetectedAt))]
public class BehaviorAnomaly : SecurityEventBase
{
    [Required]
    [MaxLength(36)]
    public string AnomalyId { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    [MaxLength(50)]
    public string AnomalyType { get; set; } = string.Empty;
    
    [Range(0, 100)]
    public double AnomalyScore { get; set; }
    
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    
    public double? BaselineValue { get; set; }
    
    public double? ObservedValue { get; set; }
    
    public double? Deviation { get; set; }
    
    [MaxLength(100)]
    public string? TimeWindow { get; set; }
    
    [MaxLength(500)]
    public string? Description { get; set; }
    
    public bool IsResolved { get; set; }
    
    public DateTime? ResolvedAt { get; set; }
    
    [MaxLength(100)]
    public string? ResolvedBy { get; set; }
    
    // Additional Context (JSON)
    public string? Context { get; set; }
    
    // Foreign Keys
    public long? UserBehaviorBaselineId { get; set; }
    
    // Navigation Properties
    public virtual UserBehaviorBaseline? UserBehaviorBaseline { get; set; }
}
```

### RequestFrequencyRecord
```csharp
[Table("RequestFrequencyRecords")]
[Index(nameof(IPAddress))]
[Index(nameof(WindowStart))]
[Index(nameof(RequestCount))]
public class RequestFrequencyRecord : BaseEntity
{
    [Required]
    [MaxLength(45)]
    public string IPAddress { get; set; } = string.Empty;
    
    public DateTime WindowStart { get; set; }
    
    public DateTime WindowEnd { get; set; }
    
    public TimeSpan WindowDuration { get; set; }
    
    public int RequestCount { get; set; }
    
    public int UniqueEndpoints { get; set; }
    
    public double AverageResponseTime { get; set; }
    
    public int ErrorCount { get; set; }
    
    public int SuccessCount { get; set; }
    
    // Request Distribution (JSON)
    public string? EndpointDistribution { get; set; }
    
    public string? MethodDistribution { get; set; }
    
    public string? StatusCodeDistribution { get; set; }
    
    // Behavioral Indicators
    public bool IsAnomalous { get; set; }
    
    public double? AnomalyScore { get; set; }
    
    [MaxLength(200)]
    public string? AnomalyReason { get; set; }
}
```

## Configuration Entities

### SecurityConfiguration
```csharp
[Table("SecurityConfigurations")]
[Index(nameof(Environment))]
[Index(nameof(IsActive))]
public class SecurityConfiguration : BaseEntity
{
    [Required]
    [MaxLength(50)]
    public string Environment { get; set; } = "Production";
    
    [Required]
    [MaxLength(100)]
    public string ConfigurationName { get; set; } = "Default";
    
    public bool IsActive { get; set; } = true;
    
    [Range(0, 100)]
    public double DefaultThreatThreshold { get; set; } = 50;
    
    public bool EnableInMemoryStorage { get; set; } = true;
    
    public bool EnableSQLitePersistence { get; set; } = false;
    
    [MaxLength(500)]
    public string? SQLiteConnectionString { get; set; }
    
    [Range(1000, 10000000)]
    public int MaxIPRecords { get; set; } = 1000000;
    
    [Range(1, 365)]
    public int DataRetentionDays { get; set; } = 90;
    
    // IP Security Settings (JSON)
    public string? IPSecuritySettings { get; set; }
    
    // Parameter Security Settings (JSON)
    public string? ParameterSecuritySettings { get; set; }
    
    // Pattern Settings (JSON)
    public string? PatternSettings { get; set; }
    
    // Real-time Monitoring Settings (JSON)
    public string? RealTimeSettings { get; set; }
    
    // Machine Learning Settings (JSON)
    public string? MachineLearningSettings { get; set; }
    
    // Notification Settings (JSON)
    public string? NotificationSettings { get; set; }
    
    // Performance Settings (JSON)
    public string? PerformanceSettings { get; set; }
    
    public DateTime EffectiveFrom { get; set; } = DateTime.UtcNow;
    
    public DateTime? EffectiveTo { get; set; }
    
    [MaxLength(500)]
    public string? Description { get; set; }
    
    [MaxLength(100)]
    public string? AppliedBy { get; set; }
}
```

### WebhookConfiguration
```csharp
[Table("WebhookConfigurations")]
[Index(nameof(Name))]
[Index(nameof(IsEnabled))]
public class WebhookConfiguration : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    
    [Required]
    [MaxLength(500)]
    [Url]
    public string Url { get; set; } = string.Empty;
    
    public bool IsEnabled { get; set; } = true;
    
    // Events (JSON array)
    [Required]
    public string Events { get; set; } = "[]";
    
    [MaxLength(256)]
    public string? Secret { get; set; }
    
    // Headers (JSON object)
    public string? Headers { get; set; }
    
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    
    [Range(0, 10)]
    public int RetryCount { get; set; } = 3;
    
    // Statistics
    public int TotalCalls { get; set; }
    
    public int SuccessfulCalls { get; set; }
    
    public int FailedCalls { get; set; }
    
    public DateTime? LastCalledAt { get; set; }
    
    public DateTime? LastSuccessAt { get; set; }
    
    public DateTime? LastFailureAt { get; set; }
    
    [MaxLength(500)]
    public string? LastError { get; set; }
    
    public double AverageResponseTime { get; set; }
}
```

## Audit and Logging Entities

### AuditEntry
```csharp
[Table("AuditEntries")]
[Index(nameof(EventType))]
[Index(nameof(Timestamp))]
[Index(nameof(UserId))]
[Index(nameof(IPAddress))]
public class AuditEntry : BaseEntity
{
    [Required]
    [MaxLength(36)]
    public string AuditId { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    [Required]
    [MaxLength(50)]
    public string EventType { get; set; } = string.Empty;
    
    [MaxLength(36)]
    public string? EventId { get; set; }
    
    [MaxLength(100)]
    public string? UserId { get; set; }
    
    [MaxLength(45)]
    public string? IPAddress { get; set; }
    
    [MaxLength(1000)]
    public string? UserAgent { get; set; }
    
    [MaxLength(36)]
    public string? SessionId { get; set; }
    
    [MaxLength(36)]
    public string? RequestId { get; set; }
    
    [MaxLength(100)]
    public string? Component { get; set; }
    
    [MaxLength(50)]
    public string? Action { get; set; }
    
    [MaxLength(500)]
    public string? Resource { get; set; }
    
    [MaxLength(50)]
    public string? Outcome { get; set; }
    
    [MaxLength(500)]
    public string? Description { get; set; }
    
    // Detailed event data (JSON)
    public string? EventData { get; set; }
    
    // Old values before change (JSON)
    public string? OldValues { get; set; }
    
    // New values after change (JSON)
    public string? NewValues { get; set; }
    
    // Additional metadata (JSON)
    public string? Metadata { get; set; }
    
    // Integrity
    [Required]
    [MaxLength(64)]
    public string Checksum { get; set; } = string.Empty;
    
    // Compliance flags
    public bool IsCompliantEvent { get; set; } = true;
    
    public bool RequiresRetention { get; set; }
    
    public DateTime? RetentionExpiresAt { get; set; }
}
```

### SecurityMetrics
```csharp
[Table("SecurityMetrics")]
[Index(nameof(MetricName))]
[Index(nameof(Timestamp))]
[Index(nameof(WindowStart))]
public class SecurityMetrics : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string MetricName { get; set; } = string.Empty;
    
    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    public DateTime WindowStart { get; set; }
    
    public DateTime WindowEnd { get; set; }
    
    public TimeSpan WindowDuration { get; set; }
    
    public double Value { get; set; }
    
    [MaxLength(50)]
    public string? Unit { get; set; }
    
    [MaxLength(50)]
    public string? MetricType { get; set; }
    
    // Dimensional data (JSON)
    public string? Dimensions { get; set; }
    
    // Statistical measures
    public double? MinValue { get; set; }
    
    public double? MaxValue { get; set; }
    
    public double? AverageValue { get; set; }
    
    public double? StandardDeviation { get; set; }
    
    public int SampleCount { get; set; }
    
    // Trend analysis
    public double? TrendDirection { get; set; }
    
    public double? PercentChange { get; set; }
    
    public bool IsAnomaly { get; set; }
    
    [MaxLength(200)]
    public string? AnomalyReason { get; set; }
}
```

## Performance Optimization Entities

### QueryPerformanceLog
```csharp
[Table("QueryPerformanceLogs")]
[Index(nameof(QueryType))]
[Index(nameof(ExecutionTime))]
[Index(nameof(Timestamp))]
public class QueryPerformanceLog : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string QueryType { get; set; } = string.Empty;
    
    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    public double ExecutionTime { get; set; }
    
    [MaxLength(2000)]
    public string? QueryDetails { get; set; }
    
    public int? RecordsAffected { get; set; }
    
    public int? MemoryUsageMB { get; set; }
    
    public bool IsSlowQuery { get; set; }
    
    [MaxLength(500)]
    public string? OptimizationSuggestion { get; set; }
    
    // Context (JSON)
    public string? Context { get; set; }
}
```

### CacheStatistics
```csharp
[Table("CacheStatistics")]
[Index(nameof(CacheKey))]
[Index(nameof(LastAccessed))]
public class CacheStatistics : BaseEntity
{
    [Required]
    [MaxLength(200)]
    public string CacheKey { get; set; } = string.Empty;
    
    [Required]
    [MaxLength(50)]
    public string CacheType { get; set; } = string.Empty;
    
    public int HitCount { get; set; }
    
    public int MissCount { get; set; }
    
    public DateTime LastAccessed { get; set; } = DateTime.UtcNow;
    
    public DateTime ExpiresAt { get; set; }
    
    public int SizeBytes { get; set; }
    
    public double AverageAccessTime { get; set; }
    
    public TimeSpan TimeToLive { get; set; }
    
    [NotMapped]
    public double HitRatio => HitCount + MissCount > 0 
        ? (double)HitCount / (HitCount + MissCount) 
        : 0;
}
```

## Entity Relationships

### Primary Relationships

```
IPSecurityRecord (1) → (∞) SecurityEvent
IPSecurityRecord (1) → (∞) ThreatEvent  
IPSecurityRecord (1) → (∞) ParameterJackingEvent

SecurityEvent (1) → (∞) PatternMatch
ThreatPattern (1) → (∞) PatternMatch

PatternTemplate (1) → (∞) ThreatPattern
PatternTemplate (1) → (∞) PatternGroup

ThreatPattern (1) → (∞) PatternTestCase

UserBehaviorBaseline (1) → (∞) BehaviorAnomaly
```

### Relationship Diagram

```
┌─────────────────────┐      ┌─────────────────────┐
│   IPSecurityRecord  │─────▶│   SecurityEvent     │
│                     │      │                     │
│ + IPAddress         │      │ + EventId           │
│ + ThreatScore       │      │ + ThreatScore       │
│ + TrustScore        │      │ + ActionTaken       │
│ + IsBlocked         │      │ + Description       │
└─────────────────────┘      └─────────────────────┘
          │                            │
          │                            │
          ▼                            ▼
┌─────────────────────┐      ┌─────────────────────┐
│    ThreatEvent      │      │    PatternMatch     │
│                     │      │                     │
│ + ThreatType        │      │ + PatternName       │
│ + ThreatScore       │      │ + MatchedValue      │
│ + Confidence        │      │ + ThreatMultiplier  │
│ + ActionTaken       │      │ + Confidence        │
└─────────────────────┘      └─────────────────────┘
                                       ▲
                                       │
                             ┌─────────────────────┐
                             │   ThreatPattern     │
                             │                     │
                             │ + Name              │
                             │ + Pattern           │
                             │ + Category          │
                             │ + ThreatMultiplier  │
                             └─────────────────────┘
                                       ▲
                                       │
                             ┌─────────────────────┐
                             │  PatternTemplate    │
                             │                     │
                             │ + Name              │
                             │ + Version           │
                             │ + Author            │
                             │ + Patterns[]        │
                             └─────────────────────┘
```

## Database Schema Design

### Table Creation Scripts

#### IPSecurityRecords Table
```sql
CREATE TABLE IPSecurityRecords (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    IPAddress TEXT NOT NULL UNIQUE,
    ThreatScore REAL NOT NULL CHECK (ThreatScore >= 0 AND ThreatScore <= 100),
    TrustScore REAL NOT NULL CHECK (TrustScore >= 0 AND TrustScore <= 100),
    RequestCount INTEGER NOT NULL CHECK (RequestCount >= 0),
    ThreatIncidents INTEGER NOT NULL CHECK (ThreatIncidents >= 0),
    FirstSeenAt TEXT NOT NULL,
    LastActivityAt TEXT NOT NULL,
    LastThreatAt TEXT,
    IsBlocked INTEGER NOT NULL CHECK (IsBlocked IN (0, 1)),
    BlockedAt TEXT,
    BlockExpiresAt TEXT,
    BlockReason TEXT,
    BlockSource TEXT,
    CountryCode TEXT,
    CountryName TEXT,
    Region TEXT,
    City TEXT,
    Latitude REAL CHECK (Latitude >= -90 AND Latitude <= 90),
    Longitude REAL CHECK (Longitude >= -180 AND Longitude <= 180),
    Timezone TEXT,
    ISP TEXT,
    IsProxy INTEGER NOT NULL CHECK (IsProxy IN (0, 1)) DEFAULT 0,
    IsTor INTEGER NOT NULL CHECK (IsTor IN (0, 1)) DEFAULT 0,
    IsHosting INTEGER NOT NULL CHECK (IsHosting IN (0, 1)) DEFAULT 0,
    AverageRequestRate REAL NOT NULL DEFAULT 0,
    AverageSessionDuration TEXT NOT NULL DEFAULT '00:00:00',
    CommonUserAgents TEXT,
    AccessPatterns TEXT,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT,
    CreatedBy TEXT,
    UpdatedBy TEXT,
    RowVersion BLOB NOT NULL
);

CREATE INDEX IX_IPSecurityRecords_IPAddress ON IPSecurityRecords(IPAddress);
CREATE INDEX IX_IPSecurityRecords_LastActivityAt ON IPSecurityRecords(LastActivityAt);
CREATE INDEX IX_IPSecurityRecords_ThreatScore ON IPSecurityRecords(ThreatScore);
CREATE INDEX IX_IPSecurityRecords_IsBlocked ON IPSecurityRecords(IsBlocked);
```

#### SecurityEvents Table
```sql
CREATE TABLE SecurityEvents (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    EventId TEXT NOT NULL UNIQUE,
    EventType TEXT NOT NULL,
    Timestamp TEXT NOT NULL,
    Severity TEXT NOT NULL,
    ThreatScore REAL NOT NULL CHECK (ThreatScore >= 0 AND ThreatScore <= 100),
    ThreatLevel TEXT,
    ActionTaken TEXT,
    Description TEXT,
    Component TEXT,
    Version TEXT,
    InstanceId TEXT,
    Hostname TEXT,
    ClientIP TEXT,
    RequestId TEXT,
    SessionId TEXT,
    UserId TEXT,
    UserAgent TEXT,
    RequestMethod TEXT,
    RequestUrl TEXT,
    RequestPath TEXT,
    QueryString TEXT,
    ContentType TEXT,
    ContentLength INTEGER,
    Protocol TEXT,
    IsEncrypted INTEGER CHECK (IsEncrypted IN (0, 1)),
    Referrer TEXT,
    ResponseStatusCode INTEGER,
    ResponseContentType TEXT,
    ResponseContentLength INTEGER,
    ResponseTime REAL,
    CountryCode TEXT,
    CountryName TEXT,
    City TEXT,
    Metadata TEXT,
    Tags TEXT,
    AdditionalData TEXT,
    IPSecurityRecordId INTEGER,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT,
    CreatedBy TEXT,
    UpdatedBy TEXT,
    RowVersion BLOB NOT NULL,
    FOREIGN KEY (IPSecurityRecordId) REFERENCES IPSecurityRecords(Id)
);

CREATE INDEX IX_SecurityEvents_EventType ON SecurityEvents(EventType);
CREATE INDEX IX_SecurityEvents_Timestamp ON SecurityEvents(Timestamp);
CREATE INDEX IX_SecurityEvents_ThreatScore ON SecurityEvents(ThreatScore);
CREATE INDEX IX_SecurityEvents_ClientIP ON SecurityEvents(ClientIP);
CREATE INDEX IX_SecurityEvents_EventId ON SecurityEvents(EventId);
```

### Indexing Strategy

#### Performance-Critical Indexes
```sql
-- High-frequency IP lookups
CREATE INDEX IX_IPSecurityRecords_Lookup ON IPSecurityRecords(IPAddress, IsBlocked, ThreatScore);

-- Time-based queries for cleanup and analytics
CREATE INDEX IX_SecurityEvents_TimeRange ON SecurityEvents(Timestamp, EventType);
CREATE INDEX IX_ThreatEvents_TimeRange ON ThreatEvents(DetectedAt, ThreatType);

-- Pattern matching performance
CREATE INDEX IX_ThreatPatterns_Active ON ThreatPatterns(IsActive, Category, Priority);
CREATE INDEX IX_PatternMatches_Pattern ON PatternMatches(PatternName, MatchedAt);

-- User behavior analysis
CREATE INDEX IX_UserBehaviorBaselines_User ON UserBehaviorBaselines(UserId, LastUpdatedAt);
CREATE INDEX IX_BehaviorAnomalies_Detection ON BehaviorAnomalies(UserId, AnomalyType, DetectedAt);
```

#### Composite Indexes for Complex Queries
```sql
-- Security event analysis
CREATE INDEX IX_SecurityEvents_Analysis ON SecurityEvents(ClientIP, EventType, Timestamp, ThreatScore);

-- Threat correlation
CREATE INDEX IX_ThreatEvents_Correlation ON ThreatEvents(ClientIP, ThreatType, DetectedAt, ThreatScore);

-- Pattern performance monitoring
CREATE INDEX IX_PatternMatches_Performance ON PatternMatches(PatternName, MatchedAt, ExecutionTimeMs);
```

## Data Validation Attributes

### Custom Validation Attributes

#### IP Address Validation
```csharp
public class IpAddressValidationAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
            return ValidationResult.Success; // Allow null for optional fields
            
        var ipString = value.ToString()!;
        
        if (IPAddress.TryParse(ipString, out var ipAddress))
        {
            // Additional validation for IP address types
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork ||
                ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return ValidationResult.Success;
            }
        }
        
        return new ValidationResult("Invalid IP address format");
    }
}
```

#### Threat Score Validation
```csharp
public class ThreatScoreValidationAttribute : RangeAttribute
{
    public ThreatScoreValidationAttribute() : base(0.0, 100.0)
    {
        ErrorMessage = "Threat score must be between 0 and 100";
    }
    
    public override bool IsValid(object? value)
    {
        if (value == null) return true; // Allow null for optional fields
        
        if (value is double doubleValue)
        {
            return doubleValue >= 0.0 && doubleValue <= 100.0 && !double.IsNaN(doubleValue) && !double.IsInfinity(doubleValue);
        }
        
        return base.IsValid(value);
    }
}
```

#### JSON Validation
```csharp
public class JsonValidationAttribute : ValidationAttribute
{
    public bool AllowNull { get; set; } = true;
    
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return AllowNull ? ValidationResult.Success : new ValidationResult("JSON value cannot be null");
            
        var jsonString = value.ToString();
        if (string.IsNullOrWhiteSpace(jsonString))
            return AllowNull ? ValidationResult.Success : new ValidationResult("JSON value cannot be empty");
            
        try
        {
            JsonDocument.Parse(jsonString);
            return ValidationResult.Success;
        }
        catch (JsonException ex)
        {
            return new ValidationResult($"Invalid JSON format: {ex.Message}");
        }
    }
}
```

### Model Validation Example
```csharp
public class SecurityEventValidator : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var results = new List<ValidationResult>();
        
        // Validate threat score consistency
        if (ThreatScore > 80 && ActionTaken == "Allow")
        {
            results.Add(new ValidationResult(
                "High threat score should not result in Allow action",
                new[] { nameof(ThreatScore), nameof(ActionTaken) }));
        }
        
        // Validate timestamp consistency
        if (Timestamp > DateTime.UtcNow.AddMinutes(5))
        {
            results.Add(new ValidationResult(
                "Event timestamp cannot be more than 5 minutes in the future",
                new[] { nameof(Timestamp) }));
        }
        
        // Validate IP address and geographic data consistency
        if (!string.IsNullOrEmpty(ClientIP) && !string.IsNullOrEmpty(CountryCode))
        {
            if (IsPrivateIP(ClientIP) && CountryCode != "XX")
            {
                results.Add(new ValidationResult(
                    "Private IP addresses should not have country codes",
                    new[] { nameof(ClientIP), nameof(CountryCode) }));
            }
        }
        
        return results;
    }
    
    private bool IsPrivateIP(string ipAddress)
    {
        if (IPAddress.TryParse(ipAddress, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            return ip.AddressFamily == AddressFamily.InterNetwork &&
                   (bytes[0] == 10 ||
                    (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                    (bytes[0] == 192 && bytes[1] == 168));
        }
        return false;
    }
}
```

## Entity Framework Configuration

### DbContext Configuration
```csharp
public class SecurityFrameworkDbContext : DbContext
{
    public SecurityFrameworkDbContext(DbContextOptions<SecurityFrameworkDbContext> options)
        : base(options)
    {
    }
    
    // DbSets
    public DbSet<IPSecurityRecord> IPSecurityRecords { get; set; }
    public DbSet<SecurityEvent> SecurityEvents { get; set; }
    public DbSet<ThreatEvent> ThreatEvents { get; set; }
    public DbSet<ParameterJackingEvent> ParameterJackingEvents { get; set; }
    public DbSet<ThreatPattern> ThreatPatterns { get; set; }
    public DbSet<PatternTemplate> PatternTemplates { get; set; }
    public DbSet<PatternMatch> PatternMatches { get; set; }
    public DbSet<PatternGroup> PatternGroups { get; set; }
    public DbSet<PatternTestCase> PatternTestCases { get; set; }
    public DbSet<UserBehaviorBaseline> UserBehaviorBaselines { get; set; }
    public DbSet<BehaviorAnomaly> BehaviorAnomalies { get; set; }
    public DbSet<RequestFrequencyRecord> RequestFrequencyRecords { get; set; }
    public DbSet<SecurityConfiguration> SecurityConfigurations { get; set; }
    public DbSet<WebhookConfiguration> WebhookConfigurations { get; set; }
    public DbSet<AuditEntry> AuditEntries { get; set; }
    public DbSet<SecurityMetrics> SecurityMetrics { get; set; }
    public DbSet<QueryPerformanceLog> QueryPerformanceLogs { get; set; }
    public DbSet<CacheStatistics> CacheStatistics { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Apply all configurations
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(SecurityFrameworkDbContext).Assembly);
        
        // Global configurations
        ConfigureGlobalSettings(modelBuilder);
        
        // Configure relationships
        ConfigureRelationships(modelBuilder);
        
        // Configure performance optimizations
        ConfigurePerformanceOptimizations(modelBuilder);
    }
    
    private void ConfigureGlobalSettings(ModelBuilder modelBuilder)
    {
        // Set default datetime kind to UTC
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                if (property.ClrType == typeof(DateTime) || property.ClrType == typeof(DateTime?))
                {
                    property.SetColumnType("TEXT");
                    property.SetValueConverter(new DateTimeToStringConverter());
                }
            }
        }
        
        // Set default string collation
        foreach (var property in modelBuilder.Model.GetEntityTypes()
            .SelectMany(t => t.GetProperties())
            .Where(p => p.ClrType == typeof(string)))
        {
            property.SetCollation("NOCASE");
        }
    }
    
    private void ConfigureRelationships(ModelBuilder modelBuilder)
    {
        // IPSecurityRecord relationships
        modelBuilder.Entity<SecurityEvent>()
            .HasOne(e => e.IPSecurityRecord)
            .WithMany(ip => ip.SecurityEvents)
            .HasForeignKey(e => e.IPSecurityRecordId)
            .OnDelete(DeleteBehavior.SetNull);
            
        modelBuilder.Entity<ThreatEvent>()
            .HasOne(e => e.IPSecurityRecord)
            .WithMany(ip => ip.ThreatEvents)
            .HasForeignKey(e => e.IPSecurityRecordId)
            .OnDelete(DeleteBehavior.SetNull);
            
        // Pattern relationships
        modelBuilder.Entity<ThreatPattern>()
            .HasMany(p => p.PatternMatches)
            .WithOne(m => m.Pattern)
            .HasForeignKey(m => m.PatternId)
            .OnDelete(DeleteBehavior.Cascade);
            
        modelBuilder.Entity<ThreatPattern>()
            .HasMany(p => p.TestCases)
            .WithOne(tc => tc.Pattern)
            .HasForeignKey(tc => tc.PatternId)
            .OnDelete(DeleteBehavior.Cascade);
            
        // Behavior relationships
        modelBuilder.Entity<UserBehaviorBaseline>()
            .HasMany(b => b.Anomalies)
            .WithOne(a => a.UserBehaviorBaseline)
            .HasForeignKey(a => a.UserBehaviorBaselineId)
            .OnDelete(DeleteBehavior.Cascade);
    }
    
    private void ConfigurePerformanceOptimizations(ModelBuilder modelBuilder)
    {
        // Configure computed columns
        modelBuilder.Entity<IPSecurityRecord>()
            .Property(e => e.IsTrusted)
            .HasComputedColumnSql("CASE WHEN TrustScore > 70 AND ThreatScore < 30 THEN 1 ELSE 0 END");
            
        modelBuilder.Entity<IPSecurityRecord>()
            .Property(e => e.IsHighRisk)
            .HasComputedColumnSql("CASE WHEN ThreatScore > 80 OR ThreatIncidents > 5 THEN 1 ELSE 0 END");
            
        // Configure memory-optimized tables for hot data
        modelBuilder.Entity<IPSecurityRecord>()
            .ToTable(tb => tb.HasComment("Primary table for IP security tracking - memory optimized"));
            
        modelBuilder.Entity<SecurityEvent>()
            .ToTable(tb => tb.HasComment("High-volume security events - partitioned by timestamp"));
    }
}
```

### Entity Type Configurations
```csharp
public class IPSecurityRecordConfiguration : IEntityTypeConfiguration<IPSecurityRecord>
{
    public void Configure(EntityTypeBuilder<IPSecurityRecord> builder)
    {
        builder.ToTable("IPSecurityRecords");
        
        // Primary key
        builder.HasKey(e => e.Id);
        
        // Unique constraints
        builder.HasIndex(e => e.IPAddress).IsUnique();
        
        // Performance indexes
        builder.HasIndex(e => e.LastActivityAt);
        builder.HasIndex(e => e.ThreatScore);
        builder.HasIndex(e => new { e.IsBlocked, e.ThreatScore });
        
        // Value conversions for complex types
        builder.Property(e => e.CommonUserAgents)
            .HasConversion(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
                
        builder.Property(e => e.AccessPatterns)
            .HasConversion(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => JsonSerializer.Deserialize<Dictionary<string, int>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, int>());
        
        // Check constraints
        builder.HasCheckConstraint("CK_IPSecurityRecord_ThreatScore", "ThreatScore >= 0 AND ThreatScore <= 100");
        builder.HasCheckConstraint("CK_IPSecurityRecord_TrustScore", "TrustScore >= 0 AND TrustScore <= 100");
        builder.HasCheckConstraint("CK_IPSecurityRecord_Coordinates", 
            "Latitude IS NULL OR (Latitude >= -90 AND Latitude <= 90) AND " +
            "Longitude IS NULL OR (Longitude >= -180 AND Longitude <= 180)");
    }
}
```

## Data Access Patterns

### Repository Pattern Implementation
```csharp
public interface IIPSecurityRepository
{
    Task<IPSecurityRecord?> GetByIPAddressAsync(string ipAddress);
    Task<IPSecurityRecord> CreateOrUpdateAsync(string ipAddress, Action<IPSecurityRecord> updateAction);
    Task<List<IPSecurityRecord>> GetHighRiskIPsAsync(double threatThreshold = 80);
    Task<List<IPSecurityRecord>> GetBlockedIPsAsync();
    Task<int> CleanupExpiredBlocksAsync();
    Task<List<IPSecurityRecord>> GetIPsByCountryAsync(string countryCode);
    Task<SecurityStatistics> GetSecurityStatisticsAsync(DateTime from, DateTime to);
}

public class IPSecurityRepository : IIPSecurityRepository
{
    private readonly SecurityFrameworkDbContext _context;
    private readonly IMemoryCache _cache;
    private readonly ILogger<IPSecurityRepository> _logger;
    
    public IPSecurityRepository(
        SecurityFrameworkDbContext context, 
        IMemoryCache cache,
        ILogger<IPSecurityRepository> logger)
    {
        _context = context;
        _cache = cache;
        _logger = logger;
    }
    
    public async Task<IPSecurityRecord?> GetByIPAddressAsync(string ipAddress)
    {
        var cacheKey = $"ip:{ipAddress}";
        
        if (_cache.TryGetValue(cacheKey, out IPSecurityRecord? cached))
        {
            return cached;
        }
        
        var record = await _context.IPSecurityRecords
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.IPAddress == ipAddress);
            
        if (record != null)
        {
            _cache.Set(cacheKey, record, TimeSpan.FromMinutes(15));
        }
        
        return record;
    }
    
    public async Task<IPSecurityRecord> CreateOrUpdateAsync(string ipAddress, Action<IPSecurityRecord> updateAction)
    {
        var record = await _context.IPSecurityRecords
            .FirstOrDefaultAsync(r => r.IPAddress == ipAddress);
            
        if (record == null)
        {
            record = new IPSecurityRecord { IPAddress = ipAddress };
            _context.IPSecurityRecords.Add(record);
        }
        
        updateAction(record);
        record.LastActivityAt = DateTime.UtcNow;
        record.UpdatedAt = DateTime.UtcNow;
        
        await _context.SaveChangesAsync();
        
        // Update cache
        var cacheKey = $"ip:{ipAddress}";
        _cache.Set(cacheKey, record, TimeSpan.FromMinutes(15));
        
        return record;
    }
    
    public async Task<List<IPSecurityRecord>> GetHighRiskIPsAsync(double threatThreshold = 80)
    {
        return await _context.IPSecurityRecords
            .AsNoTracking()
            .Where(r => r.ThreatScore >= threatThreshold)
            .OrderByDescending(r => r.ThreatScore)
            .ToListAsync();
    }
    
    public async Task<int> CleanupExpiredBlocksAsync()
    {
        var now = DateTime.UtcNow;
        var expiredBlocks = await _context.IPSecurityRecords
            .Where(r => r.IsBlocked && 
                       r.BlockExpiresAt.HasValue && 
                       r.BlockExpiresAt < now)
            .ToListAsync();
            
        foreach (var record in expiredBlocks)
        {
            record.IsBlocked = false;
            record.BlockExpiresAt = null;
            record.UpdatedAt = DateTime.UtcNow;
            
            // Remove from cache
            _cache.Remove($"ip:{record.IPAddress}");
        }
        
        await _context.SaveChangesAsync();
        return expiredBlocks.Count;
    }
}
```

### Query Optimization Patterns
```csharp
public class OptimizedSecurityQueries
{
    private readonly SecurityFrameworkDbContext _context;
    
    public OptimizedSecurityQueries(SecurityFrameworkDbContext context)
    {
        _context = context;
    }
    
    // Optimized query for real-time threat detection
    public async Task<List<RecentThreatSummary>> GetRecentThreatsAsync(TimeSpan timeWindow)
    {
        var since = DateTime.UtcNow.Subtract(timeWindow);
        
        return await _context.ThreatEvents
            .Where(e => e.DetectedAt >= since)
            .GroupBy(e => new { e.ThreatType, e.ClientIP })
            .Select(g => new RecentThreatSummary
            {
                ThreatType = g.Key.ThreatType,
                ClientIP = g.Key.ClientIP,
                Count = g.Count(),
                MaxThreatScore = g.Max(e => e.ThreatScore),
                LastDetectedAt = g.Max(e => e.DetectedAt)
            })
            .OrderByDescending(s => s.MaxThreatScore)
            .ToListAsync();
    }
    
    // Optimized pattern performance analysis
    public async Task<List<PatternPerformanceMetric>> GetPatternPerformanceAsync()
    {
        return await _context.PatternMatches
            .GroupBy(m => m.PatternName)
            .Select(g => new PatternPerformanceMetric
            {
                PatternName = g.Key,
                TotalMatches = g.Count(),
                AverageExecutionTime = g.Average(m => m.ExecutionTimeMs),
                MaxExecutionTime = g.Max(m => m.ExecutionTimeMs),
                AverageThreatMultiplier = g.Average(m => m.ThreatMultiplier),
                LastMatchedAt = g.Max(m => m.MatchedAt)
            })
            .OrderByDescending(m => m.TotalMatches)
            .ToListAsync();
    }
    
    // Bulk operations for high-volume inserts
    public async Task BulkInsertSecurityEventsAsync(IEnumerable<SecurityEvent> events)
    {
        const int batchSize = 1000;
        var eventsList = events.ToList();
        
        for (int i = 0; i < eventsList.Count; i += batchSize)
        {
            var batch = eventsList.Skip(i).Take(batchSize);
            _context.SecurityEvents.AddRange(batch);
            await _context.SaveChangesAsync();
            _context.ChangeTracker.Clear(); // Clear to prevent memory issues
        }
    }
}
```

## Migration Strategies

### Database Migration Scripts
```csharp
public partial class InitialCreate : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "IPSecurityRecords",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                IPAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false, collation: "NOCASE"),
                ThreatScore = table.Column<double>(type: "REAL", nullable: false),
                TrustScore = table.Column<double>(type: "REAL", nullable: false),
                // ... other columns
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_IPSecurityRecords", x => x.Id);
                table.CheckConstraint("CK_IPSecurityRecord_ThreatScore", "ThreatScore >= 0 AND ThreatScore <= 100");
                table.CheckConstraint("CK_IPSecurityRecord_TrustScore", "TrustScore >= 0 AND TrustScore <= 100");
            });
            
        migrationBuilder.CreateIndex(
            name: "IX_IPSecurityRecords_IPAddress",
            table: "IPSecurityRecords",
            column: "IPAddress",
            unique: true);
    }
}
```

### Data Migration Utilities
```csharp
public class DataMigrationService
{
    private readonly SecurityFrameworkDbContext _context;
    private readonly ILogger<DataMigrationService> _logger;
    
    public async Task MigrateIPSecurityDataAsync()
    {
        _logger.LogInformation("Starting IP security data migration");
        
        // Migrate in batches to avoid memory issues
        const int batchSize = 1000;
        var totalRecords = await _context.IPSecurityRecords.CountAsync();
        var processed = 0;
        
        while (processed < totalRecords)
        {
            var batch = await _context.IPSecurityRecords
                .Skip(processed)
                .Take(batchSize)
                .ToListAsync();
                
            foreach (var record in batch)
            {
                // Apply data transformations
                await ApplyDataTransformationsAsync(record);
            }
            
            await _context.SaveChangesAsync();
            processed += batch.Count;
            
            _logger.LogInformation("Migrated {Processed}/{Total} IP security records", processed, totalRecords);
        }
        
        _logger.LogInformation("IP security data migration completed");
    }
    
    private async Task ApplyDataTransformationsAsync(IPSecurityRecord record)
    {
        // Example: Update geographic data format
        if (!string.IsNullOrEmpty(record.CountryCode) && record.CountryCode.Length != 2)
        {
            record.CountryCode = await ConvertToISO2CountryCodeAsync(record.CountryCode);
        }
        
        // Example: Recalculate threat scores with new algorithm
        record.ThreatScore = await RecalculateThreatScoreAsync(record);
        
        // Example: Migrate JSON data structures
        if (!string.IsNullOrEmpty(record.CommonUserAgents))
        {
            record.CommonUserAgents = MigrateUserAgentFormat(record.CommonUserAgents);
        }
    }
}
```

---

This Data Models specification provides comprehensive coverage of all entities required for the SecurityFramework, including detailed validation, relationships, performance optimizations, and migration strategies. The models are designed for high-performance threat detection while maintaining data integrity and scalability.