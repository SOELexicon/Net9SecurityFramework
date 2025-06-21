using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SecurityFramework.Core.Configuration;

/// <summary>
/// Validator for Security Framework configuration
/// </summary>
public class ConfigurationValidator : IValidateOptions<SecurityFrameworkConfiguration>
{
    private readonly ILogger<ConfigurationValidator> _logger;

    public ConfigurationValidator(ILogger<ConfigurationValidator> logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string? name, SecurityFrameworkConfiguration options)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        try
        {
            // Validate using data annotations
            var validationContext = new ValidationContext(options);
            var validationResults = new List<ValidationResult>();
            
            if (!Validator.TryValidateObjectRecursively(options, validationContext, validationResults))
            {
                foreach (var result in validationResults)
                {
                    errors.Add($"{string.Join(", ", result.MemberNames)}: {result.ErrorMessage}");
                }
            }

            // Custom validation logic
            ValidateIPTrackingConfiguration(options.IPTracking, errors, warnings);
            ValidateParameterSecurityConfiguration(options.ParameterSecurity, errors, warnings);
            ValidatePatternMatchingConfiguration(options.PatternMatching, errors, warnings);
            ValidateThreatScoringConfiguration(options.ThreatScoring, errors, warnings);
            ValidatePersistenceConfiguration(options.Persistence, errors, warnings);
            ValidateAnalyticsConfiguration(options.Analytics, errors, warnings);
            ValidateNotificationConfiguration(options.Notifications, errors, warnings);
            ValidateRateLimitingConfiguration(options.RateLimiting, errors, warnings);
            ValidateBlocklistConfiguration(options.Blocklist, errors, warnings);
            ValidateMiddlewareConfiguration(options.Middleware, errors, warnings);
            ValidateRealTimeConfiguration(options.RealTime, errors, warnings);
            ValidatePerformanceConfiguration(options.Performance, errors, warnings);

            // Cross-component validation
            ValidateComponentInteractions(options, errors, warnings);

            // Log warnings
            foreach (var warning in warnings)
            {
                _logger.LogWarning("Configuration warning: {Warning}", warning);
            }

            if (errors.Any())
            {
                return ValidateOptionsResult.Fail(errors);
            }

            return ValidateOptionsResult.Success;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating Security Framework configuration");
            return ValidateOptionsResult.Fail($"Configuration validation failed: {ex.Message}");
        }
    }

    private static void ValidateIPTrackingConfiguration(IPTrackingConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.DefaultTrustScore < config.MinTrustScore || config.DefaultTrustScore > config.MaxTrustScore)
        {
            errors.Add("DefaultTrustScore must be between MinTrustScore and MaxTrustScore");
        }

        if (config.MinTrustScore >= config.MaxTrustScore)
        {
            errors.Add("MinTrustScore must be less than MaxTrustScore");
        }

        if (config.TrustDecayRate <= 0)
        {
            warnings.Add("TrustDecayRate of 0 means trust scores will never decay");
        }

        if (config.RetentionDays < 7)
        {
            warnings.Add("IP retention period less than 7 days may not provide sufficient historical data");
        }

        // Validate CIDR ranges
        ValidateCIDRRanges(config.TrustedRanges, "TrustedRanges", errors);
        ValidateCIDRRanges(config.BlockedRanges, "BlockedRanges", errors);
    }

    private static void ValidateParameterSecurityConfiguration(ParameterSecurityConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.MaxParametersPerRequest <= 0)
        {
            errors.Add("MaxParametersPerRequest must be greater than 0");
        }

        if (config.MaxParametersPerRequest > 500)
        {
            warnings.Add("MaxParametersPerRequest is very high and may impact performance");
        }

        if (config.MaxParameterValueLength <= 0)
        {
            errors.Add("MaxParameterValueLength must be greater than 0");
        }

        if (config.MaxParameterValueLength > 50000)
        {
            warnings.Add("MaxParameterValueLength is very high and may impact performance");
        }

        // Validate regex patterns
        foreach (var pattern in config.SuspiciousPatterns)
        {
            if (!IsValidRegexPattern(pattern))
            {
                errors.Add($"Invalid regex pattern in SuspiciousPatterns: {pattern}");
            }
        }

        if (!IsValidRegexPattern(config.AllowedParameterNamePattern))
        {
            errors.Add("AllowedParameterNamePattern is not a valid regex pattern");
        }

        // Validate IDOR settings
        var idor = config.IDORDetection;
        if (idor.SequentialAccessThreshold < 50)
        {
            warnings.Add("Low SequentialAccessThreshold may cause false positives");
        }

        if (idor.AnalysisWindowSeconds < 60)
        {
            warnings.Add("Short IDOR analysis window may not capture patterns effectively");
        }
    }

    private static void ValidatePatternMatchingConfiguration(PatternMatchingConfiguration config, List<string> errors, List<string> warnings)
    {
        if (string.IsNullOrEmpty(config.PatternDirectory))
        {
            errors.Add("PatternDirectory cannot be empty");
        }

        if (config.PatternCacheDurationMinutes <= 0)
        {
            errors.Add("PatternCacheDurationMinutes must be greater than 0");
        }

        if (config.MaxPatterns <= 0)
        {
            errors.Add("MaxPatterns must be greater than 0");
        }

        if (config.MaxPatterns > 5000)
        {
            warnings.Add("High MaxPatterns value may impact memory usage and performance");
        }

        if (config.MatchTimeoutMs <= 0)
        {
            errors.Add("MatchTimeoutMs must be greater than 0");
        }

        if (config.MatchTimeoutMs > 1000)
        {
            warnings.Add("High MatchTimeoutMs may impact request processing performance");
        }

        if (config.EnableHotReload && !config.CachePatterns)
        {
            warnings.Add("Hot reload without caching may cause performance issues");
        }
    }

    private static void ValidateThreatScoringConfiguration(ThreatScoringConfiguration config, List<string> errors, List<string> warnings)
    {
        var weights = new[]
        {
            config.BaseScoreWeight,
            config.BehavioralScoreWeight,
            config.GeographicScoreWeight,
            config.TemporalScoreWeight,
            config.PatternScoreWeight,
            config.FrequencyScoreWeight,
            config.ReputationScoreWeight
        };

        if (weights.Any(w => w < 0))
        {
            errors.Add("All threat scoring weights must be non-negative");
        }

        var totalWeight = weights.Sum();
        if (totalWeight == 0)
        {
            errors.Add("At least one threat scoring weight must be greater than 0");
        }

        if (config.MinThreatScore >= config.MaxThreatScore)
        {
            errors.Add("MinThreatScore must be less than MaxThreatScore");
        }

        // Validate thresholds
        var thresholds = config.Thresholds;
        var thresholdValues = new[] { thresholds.Low, thresholds.Medium, thresholds.High, thresholds.Critical };
        
        for (int i = 1; i < thresholdValues.Length; i++)
        {
            if (thresholdValues[i] <= thresholdValues[i - 1])
            {
                errors.Add("Threat score thresholds must be in ascending order");
                break;
            }
        }

        if (thresholds.Critical > config.MaxThreatScore)
        {
            errors.Add("Critical threshold cannot exceed MaxThreatScore");
        }
    }

    private static void ValidatePersistenceConfiguration(PersistenceConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.Enabled && string.IsNullOrEmpty(config.ConnectionString) && !config.UseInMemoryDatabase)
        {
            errors.Add("ConnectionString is required when persistence is enabled and not using in-memory database");
        }

        if (config.UseInMemoryDatabase && !string.IsNullOrEmpty(config.ConnectionString))
        {
            warnings.Add("ConnectionString is ignored when using in-memory database");
        }

        if (config.BulkOperationBatchSize <= 0)
        {
            errors.Add("BulkOperationBatchSize must be greater than 0");
        }

        if (config.BulkOperationBatchSize > 5000)
        {
            warnings.Add("Large BulkOperationBatchSize may cause memory pressure");
        }

        if (config.IPRecordCacheDurationMinutes <= 0)
        {
            errors.Add("IPRecordCacheDurationMinutes must be greater than 0");
        }

        if (config.PersistenceIntervalSeconds <= 0)
        {
            errors.Add("PersistenceIntervalSeconds must be greater than 0");
        }

        // Validate maintenance settings
        var maintenance = config.Maintenance;
        if (maintenance.SecurityIncidentRetentionDays < maintenance.ParameterIncidentRetentionDays)
        {
            warnings.Add("Parameter incident retention is longer than security incident retention");
        }

        if (maintenance.BackupIntervalHours < maintenance.MaintenanceIntervalHours)
        {
            warnings.Add("Backup interval is more frequent than maintenance interval");
        }
    }

    private static void ValidateAnalyticsConfiguration(AnalyticsConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.MetricsCacheDurationMinutes <= 0)
        {
            errors.Add("MetricsCacheDurationMinutes must be greater than 0");
        }

        if (config.DashboardCacheDurationSeconds <= 0)
        {
            errors.Add("DashboardCacheDurationSeconds must be greater than 0");
        }

        if (config.MaxEventQueueSize <= 0)
        {
            errors.Add("MaxEventQueueSize must be greater than 0");
        }

        if (config.MaxEventQueueSize < config.EventBatchSize)
        {
            errors.Add("MaxEventQueueSize must be greater than or equal to EventBatchSize");
        }

        if (config.EventBatchSize <= 0)
        {
            errors.Add("EventBatchSize must be greater than 0");
        }

        if (config.DataRetentionDays <= 0)
        {
            errors.Add("DataRetentionDays must be greater than 0");
        }

        if (config.DataRetentionDays < 7)
        {
            warnings.Add("Short data retention period may limit analytics effectiveness");
        }
    }

    private static void ValidateNotificationConfiguration(NotificationConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.ProcessingBatchSize <= 0)
        {
            errors.Add("ProcessingBatchSize must be greater than 0");
        }

        if (config.HttpTimeoutSeconds <= 0)
        {
            errors.Add("HttpTimeoutSeconds must be greater than 0");
        }

        if (config.MinimumThreatScoreForAlert < 0 || config.MinimumThreatScoreForAlert > 100)
        {
            errors.Add("MinimumThreatScoreForAlert must be between 0 and 100");
        }

        if (config.MaxRecentFailures <= 0)
        {
            errors.Add("MaxRecentFailures must be greater than 0");
        }

        if (config.MinimumThreatScoreForAlert < 50)
        {
            warnings.Add("Low MinimumThreatScoreForAlert may generate many notifications");
        }
    }

    private static void ValidateRateLimitingConfiguration(RateLimitingConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.CleanupIntervalMinutes <= 0)
        {
            errors.Add("CleanupIntervalMinutes must be greater than 0");
        }

        if (config.CounterRetentionHours <= 0)
        {
            errors.Add("CounterRetentionHours must be greater than 0");
        }

        if (string.IsNullOrEmpty(config.DefaultPolicyName))
        {
            errors.Add("DefaultPolicyName cannot be empty");
        }

        if (config.MaxCounters <= 0)
        {
            errors.Add("MaxCounters must be greater than 0");
        }

        if (config.MaxCounters < 1000)
        {
            warnings.Add("Low MaxCounters may cause frequent evictions");
        }

        if (config.CleanupIntervalMinutes > config.CounterRetentionHours * 60)
        {
            warnings.Add("Cleanup interval is longer than retention period");
        }
    }

    private static void ValidateBlocklistConfiguration(BlocklistConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.RefreshIntervalHours <= 0)
        {
            errors.Add("RefreshIntervalHours must be greater than 0");
        }

        if (config.CacheDurationMinutes <= 0)
        {
            errors.Add("CacheDurationMinutes must be greater than 0");
        }

        if (config.HttpTimeoutSeconds <= 0)
        {
            errors.Add("HttpTimeoutSeconds must be greater than 0");
        }

        // Validate sources
        foreach (var source in config.Sources)
        {
            if (string.IsNullOrEmpty(source.Name))
            {
                errors.Add("Blocklist source name cannot be empty");
            }

            if (string.IsNullOrEmpty(source.Url))
            {
                errors.Add($"Blocklist source '{source.Name}' URL cannot be empty");
            }

            if (!IsValidBlocklistSourceType(source.Type))
            {
                errors.Add($"Invalid blocklist source type: {source.Type}");
            }

            if (!IsValidBlocklistFormat(source.Format))
            {
                errors.Add($"Invalid blocklist format: {source.Format}");
            }
        }

        if (config.Enabled && config.EnableExternalSources && !config.Sources.Any())
        {
            warnings.Add("No blocklist sources configured");
        }
    }

    private static void ValidateMiddlewareConfiguration(MiddlewareConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.RequestTimeoutSeconds <= 0)
        {
            errors.Add("RequestTimeoutSeconds must be greater than 0");
        }

        if (config.RequestTimeoutSeconds > 300)
        {
            warnings.Add("Long request timeout may impact server resources");
        }

        if (!config.EnableIPSecurity && !config.EnableParameterSecurity && !config.EnableRateLimiting)
        {
            warnings.Add("All security middleware components are disabled");
        }
    }

    private static void ValidateRealTimeConfiguration(RealTimeConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.Enabled && !config.EnableSignalR && !config.EnableWebSockets)
        {
            warnings.Add("Real-time monitoring is enabled but no transport protocols are configured");
        }

        if (config.ConnectionTimeoutSeconds <= 0)
        {
            errors.Add("ConnectionTimeoutSeconds must be greater than 0");
        }

        if (config.KeepAliveIntervalSeconds <= 0)
        {
            errors.Add("KeepAliveIntervalSeconds must be greater than 0");
        }

        if (config.MaxConcurrentConnections <= 0)
        {
            errors.Add("MaxConcurrentConnections must be greater than 0");
        }

        if (config.KeepAliveIntervalSeconds >= config.ConnectionTimeoutSeconds)
        {
            warnings.Add("KeepAlive interval should be less than connection timeout");
        }
    }

    private static void ValidatePerformanceConfiguration(PerformanceConfiguration config, List<string> errors, List<string> warnings)
    {
        if (config.MaxParallelTasks <= 0)
        {
            errors.Add("MaxParallelTasks must be greater than 0");
        }

        if (config.MemoryCacheSizeLimitMB <= 0)
        {
            errors.Add("MemoryCacheSizeLimitMB must be greater than 0");
        }

        if (config.CacheSlidingExpirationMinutes <= 0)
        {
            errors.Add("CacheSlidingExpirationMinutes must be greater than 0");
        }

        if (config.ResponseTimeThresholdMs <= 0)
        {
            errors.Add("ResponseTimeThresholdMs must be greater than 0");
        }

        if (config.MaxParallelTasks > Environment.ProcessorCount * 4)
        {
            warnings.Add("MaxParallelTasks is much higher than processor count");
        }

        if (config.MemoryCacheSizeLimitMB > 1000)
        {
            warnings.Add("High memory cache limit may impact system memory");
        }
    }

    private static void ValidateComponentInteractions(SecurityFrameworkConfiguration config, List<string> errors, List<string> warnings)
    {
        // Analytics requires persistence for meaningful data
        if (config.Analytics.Enabled && !config.Persistence.Enabled)
        {
            warnings.Add("Analytics is enabled but persistence is disabled - limited analytics data will be available");
        }

        // Pattern matching requires valid directory when enabled
        if (config.PatternMatching.Enabled && config.PatternMatching.LoadOnStartup && 
            !Directory.Exists(config.PatternMatching.PatternDirectory))
        {
            warnings.Add($"Pattern directory '{config.PatternMatching.PatternDirectory}' does not exist");
        }

        // Real-time features require analytics
        if (config.RealTime.Enabled && !config.Analytics.Enabled)
        {
            warnings.Add("Real-time monitoring is enabled but analytics is disabled");
        }

        // Notification requires analytics for generating alerts
        if (config.Notifications.Enabled && !config.Analytics.Enabled)
        {
            warnings.Add("Notifications are enabled but analytics is disabled - limited alerting functionality");
        }

        // Performance tuning warnings
        if (config.Analytics.EnableRealTimeAnalytics && !config.Analytics.UseAsyncProcessing)
        {
            warnings.Add("Real-time analytics without async processing may impact performance");
        }
    }

    private static void ValidateCIDRRanges(List<string> ranges, string propertyName, List<string> errors)
    {
        foreach (var range in ranges)
        {
            if (!IsValidCIDRRange(range))
            {
                errors.Add($"Invalid CIDR range in {propertyName}: {range}");
            }
        }
    }

    private static bool IsValidCIDRRange(string cidr)
    {
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) return false;

            if (!System.Net.IPAddress.TryParse(parts[0], out var ip)) return false;
            if (!int.TryParse(parts[1], out var prefix)) return false;

            var maxPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            return prefix >= 0 && prefix <= maxPrefix;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsValidRegexPattern(string pattern)
    {
        try
        {
            _ = new System.Text.RegularExpressions.Regex(pattern);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsValidBlocklistSourceType(string type)
    {
        return type.Equals("File", StringComparison.OrdinalIgnoreCase) ||
               type.Equals("External", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsValidBlocklistFormat(string format)
    {
        return format.Equals("Json", StringComparison.OrdinalIgnoreCase) ||
               format.Equals("Text", StringComparison.OrdinalIgnoreCase) ||
               format.Equals("Csv", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Extension method for recursive validation
/// </summary>
public static class ValidationExtensions
{
    public static bool TryValidateObjectRecursively<T>(T obj, ValidationContext context, ICollection<ValidationResult> results)
    {
        return Validator.TryValidateObject(obj, context, results, true) && ValidateNestedObjects(obj, context, results);
    }

    private static bool ValidateNestedObjects<T>(T obj, ValidationContext context, ICollection<ValidationResult> results)
    {
        if (obj == null) return true;

        var isValid = true;
        var properties = obj.GetType().GetProperties()
            .Where(p => p.CanRead && p.PropertyType.IsClass && p.PropertyType != typeof(string));

        foreach (var property in properties)
        {
            var value = property.GetValue(obj);
            if (value == null) continue;

            var nestedContext = new ValidationContext(value);
            var nestedResults = new List<ValidationResult>();

            if (!TryValidateObjectRecursively(value, nestedContext, nestedResults))
            {
                isValid = false;
                foreach (var nestedResult in nestedResults)
                {
                    var memberNames = nestedResult.MemberNames.Select(x => $"{property.Name}.{x}");
                    results.Add(new ValidationResult(nestedResult.ErrorMessage, memberNames));
                }
            }
        }

        return isValid;
    }
}

/// <summary>
/// Extension methods for configuration validation
/// </summary>
public static class ConfigurationValidationExtensions
{
    /// <summary>
    /// Adds configuration validation for Security Framework
    /// </summary>
    public static IServiceCollection AddSecurityFrameworkConfigurationValidation(this IServiceCollection services)
    {
        services.AddSingleton<IValidateOptions<SecurityFrameworkConfiguration>, ConfigurationValidator>();
        return services;
    }
}