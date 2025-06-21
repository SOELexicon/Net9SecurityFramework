using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using SecurityFramework.Core.Abstractions;
using SecurityFramework.Data;

namespace SecurityFramework.Core.HealthChecks;

/// <summary>
/// Health check for the Security Framework components
/// </summary>
public class SecurityFrameworkHealthCheck : IHealthCheck
{
    private readonly ILogger<SecurityFrameworkHealthCheck> _logger;
    private readonly SecurityDbContext _context;
    private readonly ISecurityService? _securityService;
    private readonly IPatternService? _patternService;
    private readonly IParameterSecurityService? _parameterSecurityService;
    private readonly IBlocklistService? _blocklistService;
    private readonly IAnalyticsService? _analyticsService;
    private readonly INotificationService? _notificationService;
    private readonly IRateLimitService? _rateLimitService;

    public SecurityFrameworkHealthCheck(
        ILogger<SecurityFrameworkHealthCheck> logger,
        SecurityDbContext context,
        ISecurityService? securityService = null,
        IPatternService? patternService = null,
        IParameterSecurityService? parameterSecurityService = null,
        IBlocklistService? blocklistService = null,
        IAnalyticsService? analyticsService = null,
        INotificationService? notificationService = null,
        IRateLimitService? rateLimitService = null)
    {
        _logger = logger;
        _context = context;
        _securityService = securityService;
        _patternService = patternService;
        _parameterSecurityService = parameterSecurityService;
        _blocklistService = blocklistService;
        _analyticsService = analyticsService;
        _notificationService = notificationService;
        _rateLimitService = rateLimitService;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var healthData = new Dictionary<string, object>();
        var issues = new List<string>();
        var warnings = new List<string>();

        try
        {
            // Check database connectivity
            await CheckDatabaseHealthAsync(healthData, issues, cancellationToken);

            // Check core services
            await CheckSecurityServiceHealthAsync(healthData, issues, warnings, cancellationToken);
            await CheckPatternServiceHealthAsync(healthData, issues, warnings, cancellationToken);
            await CheckParameterSecurityServiceHealthAsync(healthData, issues, warnings, cancellationToken);

            // Check additional services
            await CheckBlocklistServiceHealthAsync(healthData, issues, warnings, cancellationToken);
            await CheckAnalyticsServiceHealthAsync(healthData, issues, warnings, cancellationToken);
            await CheckNotificationServiceHealthAsync(healthData, issues, warnings, cancellationToken);
            await CheckRateLimitServiceHealthAsync(healthData, issues, warnings, cancellationToken);

            // Check system resources
            CheckSystemResourceHealth(healthData, warnings);

            // Determine overall health status
            var status = issues.Any() ? HealthStatus.Unhealthy :
                        warnings.Any() ? HealthStatus.Degraded :
                        HealthStatus.Healthy;

            var description = status switch
            {
                HealthStatus.Healthy => "All Security Framework components are healthy",
                HealthStatus.Degraded => $"Security Framework is operational with {warnings.Count} warning(s)",
                HealthStatus.Unhealthy => $"Security Framework has {issues.Count} critical issue(s)",
                _ => "Unknown health status"
            };

            if (issues.Any())
            {
                healthData["critical_issues"] = issues;
            }

            if (warnings.Any())
            {
                healthData["warnings"] = warnings;
            }

            return new HealthCheckResult(status, description, data: healthData);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during health check");
            
            return new HealthCheckResult(
                HealthStatus.Unhealthy,
                "Health check failed due to an exception",
                ex,
                new Dictionary<string, object> { ["error"] = ex.Message });
        }
    }

    private async Task CheckDatabaseHealthAsync(Dictionary<string, object> healthData, List<string> issues, CancellationToken cancellationToken)
    {
        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Try to connect and execute a simple query
            var canConnect = await _context.Database.CanConnectAsync(cancellationToken);
            stopwatch.Stop();

            healthData["database"] = new
            {
                can_connect = canConnect,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                provider = _context.Database.ProviderName
            };

            if (!canConnect)
            {
                issues.Add("Database connectivity failed");
            }
            else if (stopwatch.ElapsedMilliseconds > 5000) // 5 second threshold
            {
                issues.Add($"Database response time is too slow: {stopwatch.ElapsedMilliseconds}ms");
            }

            // Check database size and record counts
            if (canConnect)
            {
                try
                {
                    var ipRecordCount = await _context.IPRecords.CountAsync(cancellationToken);
                    var incidentCount = await _context.SecurityIncidents.CountAsync(cancellationToken);
                    var patternCount = await _context.ThreatPatterns.CountAsync(cancellationToken);

                    healthData["database_stats"] = new
                    {
                        ip_records = ipRecordCount,
                        security_incidents = incidentCount,
                        threat_patterns = patternCount
                    };
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not retrieve database statistics");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database health check failed");
            issues.Add($"Database health check failed: {ex.Message}");
        }
    }

    private async Task CheckSecurityServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_securityService == null)
        {
            healthData["security_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test IP validation with a test IP
            var testResult = await _securityService.ValidateIPAsync("127.0.0.1", cancellationToken);
            stopwatch.Stop();

            healthData["security_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                test_validation_success = testResult != null
            };

            if (stopwatch.ElapsedMilliseconds > 100) // 100ms threshold for IP validation
            {
                warnings.Add($"SecurityService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SecurityService health check failed");
            issues.Add($"SecurityService health check failed: {ex.Message}");
            healthData["security_service"] = new { available = false, error = ex.Message };
        }
    }

    private async Task CheckPatternServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_patternService == null)
        {
            healthData["pattern_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test pattern loading
            var patterns = await _patternService.GetPatternsAsync(cancellationToken);
            stopwatch.Stop();

            var patternCount = patterns?.Count() ?? 0;

            healthData["pattern_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                pattern_count = patternCount
            };

            if (patternCount == 0)
            {
                warnings.Add("No threat patterns are loaded");
            }

            if (stopwatch.ElapsedMilliseconds > 500)
            {
                warnings.Add($"PatternService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PatternService health check failed");
            issues.Add($"PatternService health check failed: {ex.Message}");
            healthData["pattern_service"] = new { available = false, error = ex.Message };
        }
    }

    private async Task CheckParameterSecurityServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_parameterSecurityService == null)
        {
            healthData["parameter_security_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test parameter validation with sample data
            var testParameters = new Dictionary<string, string> { ["test"] = "value" };
            var testResult = await _parameterSecurityService.ValidateParametersAsync(testParameters, "test-user", cancellationToken);
            stopwatch.Stop();

            healthData["parameter_security_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                test_validation_success = testResult != null
            };

            if (stopwatch.ElapsedMilliseconds > 200)
            {
                warnings.Add($"ParameterSecurityService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ParameterSecurityService health check failed");
            issues.Add($"ParameterSecurityService health check failed: {ex.Message}");
            healthData["parameter_security_service"] = new { available = false, error = ex.Message };
        }
    }

    private async Task CheckBlocklistServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_blocklistService == null)
        {
            healthData["blocklist_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test blocklist check
            var testResult = _blocklistService.IsBlocked("127.0.0.1");
            var stats = await _blocklistService.GetStatisticsAsync(cancellationToken);
            stopwatch.Stop();

            healthData["blocklist_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                active_sources = stats.ActiveSources,
                total_blocked_ips = stats.TotalBlockedIPs,
                total_blocked_ranges = stats.TotalBlockedRanges
            };

            if (stats.ActiveSources == 0)
            {
                warnings.Add("No active blocklist sources configured");
            }

            if (stopwatch.ElapsedMilliseconds > 50)
            {
                warnings.Add($"BlocklistService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BlocklistService health check failed");
            issues.Add($"BlocklistService health check failed: {ex.Message}");
            healthData["blocklist_service"] = new { available = false, error = ex.Message };
        }
    }

    private async Task CheckAnalyticsServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_analyticsService == null)
        {
            healthData["analytics_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test analytics service
            var dashboard = await _analyticsService.GetDashboardDataAsync(cancellationToken);
            var performance = await _analyticsService.GetPerformanceMetricsAsync(cancellationToken);
            stopwatch.Stop();

            healthData["analytics_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                dashboard_available = dashboard != null,
                performance_metrics_available = performance != null,
                memory_usage_mb = performance?.MemoryUsage / (1024 * 1024) ?? 0
            };

            if (stopwatch.ElapsedMilliseconds > 1000)
            {
                warnings.Add($"AnalyticsService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AnalyticsService health check failed");
            issues.Add($"AnalyticsService health check failed: {ex.Message}");
            healthData["analytics_service"] = new { available = false, error = ex.Message };
        }
    }

    private async Task CheckNotificationServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_notificationService == null)
        {
            healthData["notification_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test notification service
            var subscriptions = await _notificationService.GetSubscriptionsAsync(cancellationToken);
            var stats = await _notificationService.GetStatisticsAsync(TimeSpan.FromHours(1), cancellationToken);
            stopwatch.Stop();

            healthData["notification_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                active_subscriptions = subscriptions.Count(),
                total_sent = stats.TotalSent,
                success_rate = stats.TotalSent > 0 ? (double)stats.SuccessfulDeliveries / stats.TotalSent * 100 : 100
            };

            if (stats.FailedDeliveries > stats.SuccessfulDeliveries && stats.TotalSent > 10)
            {
                warnings.Add($"Notification service has high failure rate: {stats.FailedDeliveries} failures out of {stats.TotalSent} total");
            }

            if (stopwatch.ElapsedMilliseconds > 500)
            {
                warnings.Add($"NotificationService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "NotificationService health check failed");
            issues.Add($"NotificationService health check failed: {ex.Message}");
            healthData["notification_service"] = new { available = false, error = ex.Message };
        }
    }

    private async Task CheckRateLimitServiceHealthAsync(Dictionary<string, object> healthData, List<string> issues, List<string> warnings, CancellationToken cancellationToken)
    {
        if (_rateLimitService == null)
        {
            healthData["rate_limit_service"] = "Not registered";
            return;
        }

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Test rate limiting service
            var policies = await _rateLimitService.GetPoliciesAsync(cancellationToken);
            var stats = await _rateLimitService.GetStatisticsAsync(TimeSpan.FromHours(1), cancellationToken);
            stopwatch.Stop();

            healthData["rate_limit_service"] = new
            {
                available = true,
                response_time_ms = stopwatch.ElapsedMilliseconds,
                active_policies = policies.Count(),
                total_requests = stats.TotalRequests,
                blocked_requests = stats.BlockedRequests,
                block_rate = stats.TotalRequests > 0 ? (double)stats.BlockedRequests / stats.TotalRequests * 100 : 0
            };

            if (!policies.Any())
            {
                warnings.Add("No rate limiting policies are configured");
            }

            if (stopwatch.ElapsedMilliseconds > 100)
            {
                warnings.Add($"RateLimitService response time is slow: {stopwatch.ElapsedMilliseconds}ms");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RateLimitService health check failed");
            issues.Add($"RateLimitService health check failed: {ex.Message}");
            healthData["rate_limit_service"] = new { available = false, error = ex.Message };
        }
    }

    private void CheckSystemResourceHealth(Dictionary<string, object> healthData, List<string> warnings)
    {
        try
        {
            var memoryUsed = GC.GetTotalMemory(false);
            var memoryUsedMB = memoryUsed / (1024 * 1024);
            
            // Get working set memory
            var process = System.Diagnostics.Process.GetCurrentProcess();
            var workingSetMB = process.WorkingSet64 / (1024 * 1024);

            healthData["system_resources"] = new
            {
                managed_memory_mb = memoryUsedMB,
                working_set_mb = workingSetMB,
                processor_count = Environment.ProcessorCount,
                gc_gen0_collections = GC.CollectionCount(0),
                gc_gen1_collections = GC.CollectionCount(1),
                gc_gen2_collections = GC.CollectionCount(2)
            };

            // Memory usage warnings
            if (memoryUsedMB > 500) // 500MB threshold for managed memory
            {
                warnings.Add($"High managed memory usage: {memoryUsedMB}MB");
            }

            if (workingSetMB > 1000) // 1GB threshold for working set
            {
                warnings.Add($"High working set memory usage: {workingSetMB}MB");
            }

            // GC pressure warnings
            var gen2Collections = GC.CollectionCount(2);
            if (gen2Collections > 100) // Arbitrary threshold
            {
                warnings.Add($"High Gen2 GC pressure: {gen2Collections} collections");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not check system resources");
            healthData["system_resources"] = new { error = "Could not retrieve system resource information" };
        }
    }
}

/// <summary>
/// Health check for database connectivity only
/// </summary>
public class DatabaseHealthCheck : IHealthCheck
{
    private readonly SecurityDbContext _context;
    private readonly ILogger<DatabaseHealthCheck> _logger;

    public DatabaseHealthCheck(SecurityDbContext context, ILogger<DatabaseHealthCheck> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var canConnect = await _context.Database.CanConnectAsync(cancellationToken);
            stopwatch.Stop();

            if (canConnect)
            {
                return HealthCheckResult.Healthy($"Database is accessible (Response time: {stopwatch.ElapsedMilliseconds}ms)", 
                    new Dictionary<string, object>
                    {
                        ["response_time_ms"] = stopwatch.ElapsedMilliseconds,
                        ["provider"] = _context.Database.ProviderName ?? "Unknown"
                    });
            }
            else
            {
                return HealthCheckResult.Unhealthy("Cannot connect to database");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database health check failed");
            return HealthCheckResult.Unhealthy("Database health check failed", ex);
        }
    }
}

/// <summary>
/// Extension methods for registering Security Framework health checks
/// </summary>
public static class HealthCheckExtensions
{
    /// <summary>
    /// Adds Security Framework health checks
    /// </summary>
    public static IServiceCollection AddSecurityFrameworkHealthChecks(this IServiceCollection services)
    {
        services.AddHealthChecks()
            .AddCheck<SecurityFrameworkHealthCheck>("security_framework")
            .AddCheck<DatabaseHealthCheck>("security_database");

        return services;
    }

    /// <summary>
    /// Adds Security Framework health checks with custom configuration
    /// </summary>
    public static IServiceCollection AddSecurityFrameworkHealthChecks(
        this IServiceCollection services,
        Action<HealthCheckServiceOptions> configureOptions)
    {
        services.AddHealthChecks(configureOptions)
            .AddCheck<SecurityFrameworkHealthCheck>("security_framework")
            .AddCheck<DatabaseHealthCheck>("security_database");

        return services;
    }
}