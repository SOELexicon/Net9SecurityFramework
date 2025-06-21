using System.ComponentModel.DataAnnotations;

namespace SecurityFramework.Core.Configuration;

/// <summary>
/// Root configuration for the Security Framework
/// </summary>
public class SecurityFrameworkConfiguration
{
    /// <summary>
    /// IP tracking and validation configuration
    /// </summary>
    public IPTrackingConfiguration IPTracking { get; set; } = new();

    /// <summary>
    /// Parameter security configuration
    /// </summary>
    public ParameterSecurityConfiguration ParameterSecurity { get; set; } = new();

    /// <summary>
    /// Pattern matching configuration
    /// </summary>
    public PatternMatchingConfiguration PatternMatching { get; set; } = new();

    /// <summary>
    /// Threat scoring configuration
    /// </summary>
    public ThreatScoringConfiguration ThreatScoring { get; set; } = new();

    /// <summary>
    /// Data persistence configuration
    /// </summary>
    public PersistenceConfiguration Persistence { get; set; } = new();

    /// <summary>
    /// Analytics and reporting configuration
    /// </summary>
    public AnalyticsConfiguration Analytics { get; set; } = new();

    /// <summary>
    /// Notification configuration
    /// </summary>
    public NotificationConfiguration Notifications { get; set; } = new();

    /// <summary>
    /// Rate limiting configuration
    /// </summary>
    public RateLimitingConfiguration RateLimiting { get; set; } = new();

    /// <summary>
    /// Blocklist configuration
    /// </summary>
    public BlocklistConfiguration Blocklist { get; set; } = new();

    /// <summary>
    /// Middleware configuration
    /// </summary>
    public MiddlewareConfiguration Middleware { get; set; } = new();

    /// <summary>
    /// Real-time monitoring configuration
    /// </summary>
    public RealTimeConfiguration RealTime { get; set; } = new();

    /// <summary>
    /// Performance and optimization settings
    /// </summary>
    public PerformanceConfiguration Performance { get; set; } = new();
}

/// <summary>
/// IP tracking and validation configuration
/// </summary>
public class IPTrackingConfiguration
{
    /// <summary>
    /// Whether IP tracking is enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Default trust score for new IPs
    /// </summary>
    [Range(0, 100)]
    public double DefaultTrustScore { get; set; } = 50.0;

    /// <summary>
    /// Trust score decay rate per day
    /// </summary>
    [Range(0, 10)]
    public double TrustDecayRate { get; set; } = 1.0;

    /// <summary>
    /// Maximum trust score achievable
    /// </summary>
    [Range(0, 100)]
    public double MaxTrustScore { get; set; } = 100.0;

    /// <summary>
    /// Minimum trust score (floor)
    /// </summary>
    [Range(0, 100)]
    public double MinTrustScore { get; set; } = 0.0;

    /// <summary>
    /// IP data retention period in days
    /// </summary>
    [Range(1, 3650)]
    public int RetentionDays { get; set; } = 90;

    /// <summary>
    /// Whether to enable geographic data collection
    /// </summary>
    public bool EnableGeographicData { get; set; } = true;

    /// <summary>
    /// Whether to enable behavioral profiling
    /// </summary>
    public bool EnableBehavioralProfiling { get; set; } = true;

    /// <summary>
    /// Trusted IP ranges (CIDR notation)
    /// </summary>
    public List<string> TrustedRanges { get; set; } = new();

    /// <summary>
    /// Always blocked IP ranges (CIDR notation)
    /// </summary>
    public List<string> BlockedRanges { get; set; } = new();
}

/// <summary>
/// Parameter security configuration
/// </summary>
public class ParameterSecurityConfiguration
{
    /// <summary>
    /// Whether parameter security is enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether to enable IDOR detection
    /// </summary>
    public bool EnableIDORDetection { get; set; } = true;

    /// <summary>
    /// Whether to enable parameter enumeration detection
    /// </summary>
    public bool EnableEnumerationDetection { get; set; } = true;

    /// <summary>
    /// Maximum parameter count per request
    /// </summary>
    [Range(1, 1000)]
    public int MaxParametersPerRequest { get; set; } = 100;

    /// <summary>
    /// Maximum parameter value length
    /// </summary>
    [Range(1, 100000)]
    public int MaxParameterValueLength { get; set; } = 10000;

    /// <summary>
    /// Suspicious parameter patterns (regex)
    /// </summary>
    public List<string> SuspiciousPatterns { get; set; } = new()
    {
        @"\.\./",
        @"<script",
        @"union\s+select",
        @"exec\s*\(",
        @"javascript:",
        @"vbscript:"
    };

    /// <summary>
    /// Allowed parameter name characters (regex)
    /// </summary>
    [Required]
    public string AllowedParameterNamePattern { get; set; } = @"^[a-zA-Z0-9_\-\.]+$";

    /// <summary>
    /// IDOR detection settings
    /// </summary>
    public IDORDetectionSettings IDORDetection { get; set; } = new();
}

/// <summary>
/// IDOR detection settings
/// </summary>
public class IDORDetectionSettings
{
    /// <summary>
    /// Minimum requests before IDOR analysis
    /// </summary>
    [Range(1, 1000)]
    public int MinRequestsForAnalysis { get; set; } = 5;

    /// <summary>
    /// Time window for IDOR analysis
    /// </summary>
    [Range(1, 3600)]
    public int AnalysisWindowSeconds { get; set; } = 300;

    /// <summary>
    /// Sequential access threshold (percentage)
    /// </summary>
    [Range(0, 100)]
    public double SequentialAccessThreshold { get; set; } = 80.0;

    /// <summary>
    /// Resource ID formats to monitor
    /// </summary>
    public List<string> MonitoredIdFormats { get; set; } = new() { "integer", "guid", "uuid" };
}

/// <summary>
/// Pattern matching configuration
/// </summary>
public class PatternMatchingConfiguration
{
    /// <summary>
    /// Whether pattern matching is enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Directory containing pattern files
    /// </summary>
    [Required]
    public string PatternDirectory { get; set; } = "patterns";

    /// <summary>
    /// Whether to enable hot reload of patterns
    /// </summary>
    public bool EnableHotReload { get; set; } = true;

    /// <summary>
    /// Whether to cache patterns in memory
    /// </summary>
    public bool CachePatterns { get; set; } = true;

    /// <summary>
    /// Pattern cache duration in minutes
    /// </summary>
    [Range(1, 1440)]
    public int PatternCacheDurationMinutes { get; set; } = 30;

    /// <summary>
    /// Maximum number of patterns to load
    /// </summary>
    [Range(1, 10000)]
    public int MaxPatterns { get; set; } = 1000;

    /// <summary>
    /// Pattern matching timeout in milliseconds
    /// </summary>
    [Range(1, 10000)]
    public int MatchTimeoutMs { get; set; } = 100;

    /// <summary>
    /// Whether to load patterns on startup
    /// </summary>
    public bool LoadOnStartup { get; set; } = true;
}

/// <summary>
/// Threat scoring configuration
/// </summary>
public class ThreatScoringConfiguration
{
    /// <summary>
    /// Base score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double BaseScoreWeight { get; set; } = 1.0;

    /// <summary>
    /// Behavioral score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double BehavioralScoreWeight { get; set; } = 0.8;

    /// <summary>
    /// Geographic score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double GeographicScoreWeight { get; set; } = 0.6;

    /// <summary>
    /// Temporal score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double TemporalScoreWeight { get; set; } = 0.7;

    /// <summary>
    /// Pattern score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double PatternScoreWeight { get; set; } = 1.2;

    /// <summary>
    /// Frequency score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double FrequencyScoreWeight { get; set; } = 0.9;

    /// <summary>
    /// Reputation score weight in final calculation
    /// </summary>
    [Range(0, 10)]
    public double ReputationScoreWeight { get; set; } = 1.0;

    /// <summary>
    /// Minimum threat score
    /// </summary>
    [Range(0, 100)]
    public double MinThreatScore { get; set; } = 0.0;

    /// <summary>
    /// Maximum threat score
    /// </summary>
    [Range(0, 100)]
    public double MaxThreatScore { get; set; } = 100.0;

    /// <summary>
    /// Threat score thresholds
    /// </summary>
    public ThreatScoreThresholds Thresholds { get; set; } = new();
}

/// <summary>
/// Threat score thresholds
/// </summary>
public class ThreatScoreThresholds
{
    /// <summary>
    /// Low threat threshold
    /// </summary>
    [Range(0, 100)]
    public double Low { get; set; } = 30.0;

    /// <summary>
    /// Medium threat threshold
    /// </summary>
    [Range(0, 100)]
    public double Medium { get; set; } = 60.0;

    /// <summary>
    /// High threat threshold
    /// </summary>
    [Range(0, 100)]
    public double High { get; set; } = 80.0;

    /// <summary>
    /// Critical threat threshold
    /// </summary>
    [Range(0, 100)]
    public double Critical { get; set; } = 95.0;
}

/// <summary>
/// Data persistence configuration
/// </summary>
public class PersistenceConfiguration
{
    /// <summary>
    /// Whether to enable persistence
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Database connection string
    /// </summary>
    public string? ConnectionString { get; set; }

    /// <summary>
    /// Whether to use in-memory database
    /// </summary>
    public bool UseInMemoryDatabase { get; set; } = false;

    /// <summary>
    /// Whether to enable Write-Ahead Logging
    /// </summary>
    public bool EnableWALMode { get; set; } = true;

    /// <summary>
    /// Batch size for bulk operations
    /// </summary>
    [Range(1, 10000)]
    public int BulkOperationBatchSize { get; set; } = 1000;

    /// <summary>
    /// Cache duration for IP records in minutes
    /// </summary>
    [Range(1, 1440)]
    public int IPRecordCacheDurationMinutes { get; set; } = 60;

    /// <summary>
    /// Persistence interval in seconds
    /// </summary>
    [Range(1, 3600)]
    public int PersistenceIntervalSeconds { get; set; } = 30;

    /// <summary>
    /// Whether to ensure database is created on startup
    /// </summary>
    public bool EnsureDatabaseCreated { get; set; } = true;

    /// <summary>
    /// Database maintenance settings
    /// </summary>
    public DatabaseMaintenanceSettings Maintenance { get; set; } = new();
}

/// <summary>
/// Database maintenance settings
/// </summary>
public class DatabaseMaintenanceSettings
{
    /// <summary>
    /// Maintenance interval in hours
    /// </summary>
    [Range(1, 168)]
    public int MaintenanceIntervalHours { get; set; } = 24;

    /// <summary>
    /// Whether to enable automatic vacuum
    /// </summary>
    public bool EnableAutomaticVacuum { get; set; } = true;

    /// <summary>
    /// Whether to enable data cleanup
    /// </summary>
    public bool EnableDataCleanup { get; set; } = true;

    /// <summary>
    /// Security incident retention days
    /// </summary>
    [Range(1, 3650)]
    public int SecurityIncidentRetentionDays { get; set; } = 90;

    /// <summary>
    /// Parameter incident retention days
    /// </summary>
    [Range(1, 3650)]
    public int ParameterIncidentRetentionDays { get; set; } = 30;

    /// <summary>
    /// Whether to enable backup
    /// </summary>
    public bool EnableBackup { get; set; } = true;

    /// <summary>
    /// Backup interval in hours
    /// </summary>
    [Range(1, 168)]
    public int BackupIntervalHours { get; set; } = 24;
}

/// <summary>
/// Analytics configuration
/// </summary>
public class AnalyticsConfiguration
{
    /// <summary>
    /// Whether analytics are enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Metrics cache duration in minutes
    /// </summary>
    [Range(1, 1440)]
    public int MetricsCacheDurationMinutes { get; set; } = 15;

    /// <summary>
    /// Dashboard cache duration in seconds
    /// </summary>
    [Range(1, 3600)]
    public int DashboardCacheDurationSeconds { get; set; } = 30;

    /// <summary>
    /// Maximum event queue size
    /// </summary>
    [Range(100, 100000)]
    public int MaxEventQueueSize { get; set; } = 10000;

    /// <summary>
    /// Event batch processing size
    /// </summary>
    [Range(1, 1000)]
    public int EventBatchSize { get; set; } = 100;

    /// <summary>
    /// Whether to enable real-time analytics
    /// </summary>
    public bool EnableRealTimeAnalytics { get; set; } = true;

    /// <summary>
    /// Data retention period in days
    /// </summary>
    [Range(1, 3650)]
    public int DataRetentionDays { get; set; } = 90;
}

/// <summary>
/// Notification configuration
/// </summary>
public class NotificationConfiguration
{
    /// <summary>
    /// Whether notifications are enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether to use async processing
    /// </summary>
    public bool UseAsyncProcessing { get; set; } = true;

    /// <summary>
    /// Processing batch size
    /// </summary>
    [Range(1, 1000)]
    public int ProcessingBatchSize { get; set; } = 50;

    /// <summary>
    /// HTTP timeout for webhooks in seconds
    /// </summary>
    [Range(1, 300)]
    public int HttpTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Minimum threat score for alerts
    /// </summary>
    [Range(0, 100)]
    public double MinimumThreatScoreForAlert { get; set; } = 70.0;

    /// <summary>
    /// Whether to test subscriptions on creation
    /// </summary>
    public bool TestSubscriptionsOnCreate { get; set; } = true;

    /// <summary>
    /// Maximum recent failures to track
    /// </summary>
    [Range(10, 1000)]
    public int MaxRecentFailures { get; set; } = 100;
}

/// <summary>
/// Rate limiting configuration
/// </summary>
public class RateLimitingConfiguration
{
    /// <summary>
    /// Whether rate limiting is enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Cleanup interval in minutes
    /// </summary>
    [Range(1, 60)]
    public int CleanupIntervalMinutes { get; set; } = 5;

    /// <summary>
    /// Counter retention period in hours
    /// </summary>
    [Range(1, 24)]
    public int CounterRetentionHours { get; set; } = 1;

    /// <summary>
    /// Whether to enable adaptive limiting
    /// </summary>
    public bool EnableAdaptiveLimiting { get; set; } = false;

    /// <summary>
    /// Default policy name
    /// </summary>
    [Required]
    public string DefaultPolicyName { get; set; } = "Default";

    /// <summary>
    /// Whether to include headers
    /// </summary>
    public bool IncludeHeaders { get; set; } = true;

    /// <summary>
    /// Maximum counters in memory
    /// </summary>
    [Range(1000, 1000000)]
    public int MaxCounters { get; set; } = 100000;

    /// <summary>
    /// Whether to log decisions
    /// </summary>
    public bool LogDecisions { get; set; } = false;
}

/// <summary>
/// Blocklist configuration
/// </summary>
public class BlocklistConfiguration
{
    /// <summary>
    /// Whether blocklist is enabled
    /// </summary>
    [Required]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether to enable external sources
    /// </summary>
    public bool EnableExternalSources { get; set; } = true;

    /// <summary>
    /// Refresh interval in hours
    /// </summary>
    [Range(1, 168)]
    public int RefreshIntervalHours { get; set; } = 6;

    /// <summary>
    /// Cache duration in minutes
    /// </summary>
    [Range(1, 1440)]
    public int CacheDurationMinutes { get; set; } = 30;

    /// <summary>
    /// HTTP timeout in seconds
    /// </summary>
    [Range(1, 300)]
    public int HttpTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Blocklist sources
    /// </summary>
    public List<BlocklistSourceConfiguration> Sources { get; set; } = new();
}

/// <summary>
/// Blocklist source configuration
/// </summary>
public class BlocklistSourceConfiguration
{
    /// <summary>
    /// Source name
    /// </summary>
    [Required]
    public string Name { get; set; } = "";

    /// <summary>
    /// Source URL or file path
    /// </summary>
    [Required]
    public string Url { get; set; } = "";

    /// <summary>
    /// Source type (File, External)
    /// </summary>
    [Required]
    public string Type { get; set; } = "File";

    /// <summary>
    /// Data format (Json, Text, Csv)
    /// </summary>
    [Required]
    public string Format { get; set; } = "Text";

    /// <summary>
    /// Source category
    /// </summary>
    public string Category { get; set; } = "General";

    /// <summary>
    /// Whether source is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;
}

/// <summary>
/// Middleware configuration
/// </summary>
public class MiddlewareConfiguration
{
    /// <summary>
    /// Whether to enable IP security middleware
    /// </summary>
    public bool EnableIPSecurity { get; set; } = true;

    /// <summary>
    /// Whether to enable parameter security middleware
    /// </summary>
    public bool EnableParameterSecurity { get; set; } = true;

    /// <summary>
    /// Whether to enable request logging middleware
    /// </summary>
    public bool EnableRequestLogging { get; set; } = true;

    /// <summary>
    /// Whether to enable rate limiting middleware
    /// </summary>
    public bool EnableRateLimiting { get; set; } = true;

    /// <summary>
    /// Request timeout in seconds
    /// </summary>
    [Range(1, 300)]
    public int RequestTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Whether to log blocked requests
    /// </summary>
    public bool LogBlockedRequests { get; set; } = true;

    /// <summary>
    /// Whether to return detailed errors
    /// </summary>
    public bool ReturnDetailedErrors { get; set; } = false;

    /// <summary>
    /// Excluded paths for middleware
    /// </summary>
    public List<string> ExcludedPaths { get; set; } = new() { "/health", "/metrics" };
}

/// <summary>
/// Real-time monitoring configuration
/// </summary>
public class RealTimeConfiguration
{
    /// <summary>
    /// Whether real-time monitoring is enabled
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Whether to enable SignalR
    /// </summary>
    public bool EnableSignalR { get; set; } = false;

    /// <summary>
    /// Whether to enable WebSockets
    /// </summary>
    public bool EnableWebSockets { get; set; } = false;

    /// <summary>
    /// Connection timeout in seconds
    /// </summary>
    [Range(1, 300)]
    public int ConnectionTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Keep alive interval in seconds
    /// </summary>
    [Range(1, 300)]
    public int KeepAliveIntervalSeconds { get; set; } = 15;

    /// <summary>
    /// Maximum concurrent connections
    /// </summary>
    [Range(1, 10000)]
    public int MaxConcurrentConnections { get; set; } = 1000;
}

/// <summary>
/// Performance configuration
/// </summary>
public class PerformanceConfiguration
{
    /// <summary>
    /// Maximum parallel tasks
    /// </summary>
    [Range(1, 100)]
    public int MaxParallelTasks { get; set; } = Environment.ProcessorCount;

    /// <summary>
    /// Memory cache size limit in MB
    /// </summary>
    [Range(10, 10000)]
    public int MemoryCacheSizeLimitMB { get; set; } = 100;

    /// <summary>
    /// Sliding expiration for cache entries in minutes
    /// </summary>
    [Range(1, 1440)]
    public int CacheSlidingExpirationMinutes { get; set; } = 30;

    /// <summary>
    /// Whether to enable performance counters
    /// </summary>
    public bool EnablePerformanceCounters { get; set; } = true;

    /// <summary>
    /// Whether to enable detailed timing
    /// </summary>
    public bool EnableDetailedTiming { get; set; } = false;

    /// <summary>
    /// Response time threshold in milliseconds for warnings
    /// </summary>
    [Range(1, 10000)]
    public int ResponseTimeThresholdMs { get; set; } = 100;
}