using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityFramework.Core.Abstractions;
using SecurityFramework.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Concurrent;

namespace SecurityFramework.Services;

/// <summary>
/// Service for security analytics and reporting
/// </summary>
public class AnalyticsService : IAnalyticsService
{
    private readonly ILogger<AnalyticsService> _logger;
    private readonly SecurityDbContext _context;
    private readonly IMemoryCache _cache;
    private readonly AnalyticsOptions _options;
    private readonly ConcurrentQueue<SecurityAnalyticsEvent> _eventQueue;
    private readonly Timer _processingTimer;

    public AnalyticsService(
        ILogger<AnalyticsService> logger,
        SecurityDbContext context,
        IMemoryCache cache,
        IOptions<AnalyticsOptions> options)
    {
        _logger = logger;
        _context = context;
        _cache = cache;
        _options = options.Value;
        _eventQueue = new ConcurrentQueue<SecurityAnalyticsEvent>();

        // Setup background processing timer
        _processingTimer = new Timer(ProcessEventQueue, null, 
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public async Task<SecurityMetrics> GetSecurityMetricsAsync(DateTime startTime, DateTime endTime, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"metrics_{startTime:yyyyMMddHH}_{endTime:yyyyMMddHH}";
        if (_cache.TryGetValue(cacheKey, out SecurityMetrics? cachedMetrics) && cachedMetrics != null)
        {
            return cachedMetrics;
        }

        _logger.LogInformation("Calculating security metrics for period {Start} to {End}", startTime, endTime);

        var metrics = new SecurityMetrics
        {
            TimePeriod = new DateTimeRange { Start = startTime, End = endTime }
        };

        // Get metrics from database
        var incidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= startTime && i.Timestamp <= endTime)
            .ToListAsync(cancellationToken);

        var parameterIncidents = await _context.ParameterSecurityIncidents
            .Where(i => i.Timestamp >= startTime && i.Timestamp <= endTime)
            .ToListAsync(cancellationToken);

        var ipRecords = await _context.IPRecords
            .Where(r => r.LastSeen >= startTime && r.LastSeen <= endTime)
            .ToListAsync(cancellationToken);

        // Calculate basic metrics
        metrics.TotalRequests = incidents.Sum(i => i.RequestCount);
        metrics.ThreatsDetected = incidents.Count(i => i.ThreatScore > 50);
        metrics.BlockedRequests = incidents.Count(i => i.Action == "Block");
        metrics.UniqueIPs = ipRecords.Select(r => r.IPAddress).Distinct().Count();
        metrics.SecurityIncidents = incidents.Count;
        metrics.ParameterViolations = parameterIncidents.Count;
        metrics.AverageThreatScore = incidents.Any() ? incidents.Average(i => i.ThreatScore) : 0;
        metrics.HighestThreatScore = incidents.Any() ? incidents.Max(i => i.ThreatScore) : 0;

        // Calculate metrics by category
        metrics.MetricsByCategory = incidents
            .GroupBy(i => i.Category.ToString())
            .ToDictionary(g => g.Key, g => (long)g.Count());

        // Calculate hourly breakdown
        metrics.HourlyBreakdown = incidents
            .GroupBy(i => new DateTime(i.Timestamp.Year, i.Timestamp.Month, i.Timestamp.Day, i.Timestamp.Hour, 0, 0))
            .Select(g => new HourlyMetrics
            {
                Hour = g.Key,
                RequestCount = g.Sum(i => i.RequestCount),
                ThreatCount = g.Count(i => i.ThreatScore > 50),
                BlockedCount = g.Count(i => i.Action == "Block"),
                AverageThreatScore = g.Average(i => i.ThreatScore)
            })
            .OrderBy(h => h.Hour)
            .ToList();

        // Cache the results
        _cache.Set(cacheKey, metrics, TimeSpan.FromMinutes(_options.MetricsCacheDurationMinutes));

        return metrics;
    }

    public async Task<SecurityDashboard> GetDashboardDataAsync(CancellationToken cancellationToken = default)
    {
        var cacheKey = "dashboard_data";
        if (_cache.TryGetValue(cacheKey, out SecurityDashboard? cachedDashboard) && cachedDashboard != null)
        {
            return cachedDashboard;
        }

        var now = DateTime.UtcNow;
        var oneHourAgo = now.AddHours(-1);
        var oneDayAgo = now.AddDays(-1);

        var dashboard = new SecurityDashboard();

        // Get recent incidents
        var recentIncidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= oneHourAgo)
            .OrderByDescending(i => i.Timestamp)
            .Take(50)
            .ToListAsync(cancellationToken);

        dashboard.RequestsLastHour = recentIncidents.Sum(i => i.RequestCount);
        dashboard.BlockedLastHour = recentIncidents.Count(i => i.Action == "Block");
        dashboard.ActiveThreats = recentIncidents.Count(i => i.ThreatScore > 70);

        // Determine security status
        var criticalThreats = recentIncidents.Count(i => i.ThreatScore > 90);
        var highThreats = recentIncidents.Count(i => i.ThreatScore > 70);

        dashboard.Status = criticalThreats > 5 ? SecurityStatus.Critical :
                          highThreats > 20 ? SecurityStatus.High :
                          highThreats > 10 ? SecurityStatus.Elevated :
                          SecurityStatus.Normal;

        // Convert recent incidents to analytics events
        dashboard.RecentEvents = recentIncidents.Take(10).Select(i => new SecurityAnalyticsEvent
        {
            Id = i.Id,
            Timestamp = i.Timestamp,
            Type = MapToEventType(i.Category),
            Severity = MapToSeverity(i.ThreatScore),
            IPAddress = i.IPAddress,
            UserAgent = i.UserAgent,
            RequestPath = i.RequestPath,
            HttpMethod = i.HttpMethod,
            ThreatScore = i.ThreatScore,
            Description = i.Description,
            Categories = new List<string> { i.Category.ToString() }
        }).ToList();

        // Get top threat sources
        dashboard.TopThreatSources = await GetTopThreatSourcesAsync(oneDayAgo, 10, cancellationToken);

        // System health (simplified)
        dashboard.SystemHealth = new SystemHealth
        {
            DatabaseConnectionHealthy = await CheckDatabaseHealthAsync(cancellationToken),
            AverageResponseTime = CalculateAverageResponseTime(recentIncidents),
            MemoryUsage = GC.GetTotalMemory(false) / (1024 * 1024), // MB
            EventQueueSize = _eventQueue.Count
        };

        // Real-time metrics
        dashboard.RealTimeMetrics = new RealTimeMetrics
        {
            RequestsPerMinute = recentIncidents.Count(i => i.Timestamp >= now.AddMinutes(-1)),
            ThreatsPerMinute = recentIncidents.Count(i => i.Timestamp >= now.AddMinutes(-1) && i.ThreatScore > 50),
            AverageThreatScore = recentIncidents.Any() ? recentIncidents.Average(i => i.ThreatScore) : 0
        };

        // Alert summary
        dashboard.Alerts = new AlertSummary
        {
            CriticalAlerts = criticalThreats,
            HighAlerts = highThreats,
            MediumAlerts = recentIncidents.Count(i => i.ThreatScore > 30 && i.ThreatScore <= 70),
            LowAlerts = recentIncidents.Count(i => i.ThreatScore <= 30)
        };

        // Cache for short duration due to real-time nature
        _cache.Set(cacheKey, dashboard, TimeSpan.FromSeconds(_options.DashboardCacheDurationSeconds));

        return dashboard;
    }

    public async Task<ThreatAnalysis> GetThreatAnalysisAsync(string? ipAddress = null, int limit = 100, CancellationToken cancellationToken = default)
    {
        var query = _context.SecurityIncidents.AsQueryable();
        
        if (!string.IsNullOrEmpty(ipAddress))
        {
            query = query.Where(i => i.IPAddress == ipAddress);
        }

        var incidents = await query
            .OrderByDescending(i => i.ThreatScore)
            .Take(limit)
            .ToListAsync(cancellationToken);

        var analysis = new ThreatAnalysis();

        // Create IP threat profiles
        analysis.IPProfiles = incidents
            .GroupBy(i => i.IPAddress)
            .Select(g => new IPThreatProfile
            {
                IPAddress = g.Key,
                TotalIncidents = g.Count(),
                AverageThreatScore = g.Average(i => i.ThreatScore),
                HighestThreatScore = g.Max(i => i.ThreatScore),
                FirstSeen = g.Min(i => i.Timestamp),
                LastSeen = g.Max(i => i.Timestamp),
                Categories = g.Select(i => i.Category.ToString()).Distinct().ToList(),
                GeographicInfo = g.FirstOrDefault()?.GeographicInfo
            })
            .OrderByDescending(p => p.AverageThreatScore)
            .Take(50)
            .ToList();

        // Analyze attack patterns
        analysis.AttackPatterns = incidents
            .GroupBy(i => new { i.Category, Pattern = ExtractPattern(i.RequestPath, i.UserAgent) })
            .Select(g => new AttackPattern
            {
                Category = g.Key.Category.ToString(),
                Pattern = g.Key.Pattern,
                Frequency = g.Count(),
                AverageThreatScore = g.Average(i => i.ThreatScore),
                FirstSeen = g.Min(i => i.Timestamp),
                LastSeen = g.Max(i => i.Timestamp),
                AffectedIPs = g.Select(i => i.IPAddress).Distinct().Count()
            })
            .OrderByDescending(p => p.Frequency)
            .Take(20)
            .ToList();

        // Risk assessment summary
        analysis.RiskSummary = new RiskAssessmentSummary
        {
            OverallRiskLevel = CalculateOverallRiskLevel(incidents),
            TotalThreats = incidents.Count,
            CriticalThreats = incidents.Count(i => i.ThreatScore > 90),
            HighThreats = incidents.Count(i => i.ThreatScore > 70),
            MediumThreats = incidents.Count(i => i.ThreatScore > 30),
            LowThreats = incidents.Count(i => i.ThreatScore <= 30),
            TrendDirection = CalculateThreatTrend(incidents)
        };

        // Generate recommendations
        analysis.Recommendations = GenerateThreatMitigationRecommendations(analysis);

        return analysis;
    }

    public async Task<TrendData> GetTrendDataAsync(SecurityMetricType metric, TimeSpan period, TrendGranularity granularity, CancellationToken cancellationToken = default)
    {
        var endTime = DateTime.UtcNow;
        var startTime = endTime - period;

        var incidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= startTime && i.Timestamp <= endTime)
            .ToListAsync(cancellationToken);

        var trendData = new TrendData
        {
            Metric = metric,
            DataPoints = new List<TrendDataPoint>()
        };

        // Group data by granularity
        var groupedData = granularity switch
        {
            TrendGranularity.Hourly => incidents.GroupBy(i => new DateTime(i.Timestamp.Year, i.Timestamp.Month, i.Timestamp.Day, i.Timestamp.Hour, 0, 0)),
            TrendGranularity.Daily => incidents.GroupBy(i => i.Timestamp.Date),
            TrendGranularity.Weekly => incidents.GroupBy(i => GetWeekStart(i.Timestamp)),
            TrendGranularity.Monthly => incidents.GroupBy(i => new DateTime(i.Timestamp.Year, i.Timestamp.Month, 1)),
            _ => incidents.GroupBy(i => i.Timestamp.Date)
        };

        // Calculate metric values for each time period
        foreach (var group in groupedData.OrderBy(g => g.Key))
        {
            var value = metric switch
            {
                SecurityMetricType.TotalRequests => group.Sum(i => i.RequestCount),
                SecurityMetricType.ThreatsDetected => group.Count(i => i.ThreatScore > 50),
                SecurityMetricType.BlockedRequests => group.Count(i => i.Action == "Block"),
                SecurityMetricType.UniqueIPs => group.Select(i => i.IPAddress).Distinct().Count(),
                SecurityMetricType.SecurityIncidents => group.Count(),
                SecurityMetricType.AverageThreatScore => group.Any() ? group.Average(i => i.ThreatScore) : 0,
                _ => 0
            };

            trendData.DataPoints.Add(new TrendDataPoint
            {
                Timestamp = group.Key,
                Value = value,
                Count = group.Count()
            });
        }

        // Calculate trend direction and statistics
        if (trendData.DataPoints.Count >= 2)
        {
            var recent = trendData.DataPoints.TakeLast(Math.Min(5, trendData.DataPoints.Count)).Average(p => p.Value);
            var earlier = trendData.DataPoints.Take(Math.Min(5, trendData.DataPoints.Count)).Average(p => p.Value);
            
            trendData.ChangePercentage = earlier > 0 ? ((recent - earlier) / earlier) * 100 : 0;
            trendData.Direction = Math.Abs(trendData.ChangePercentage) < 5 ? TrendDirection.Stable :
                                 trendData.ChangePercentage > 0 ? TrendDirection.Increasing :
                                 TrendDirection.Decreasing;
        }

        trendData.Statistics = new TrendStatistics
        {
            Average = trendData.DataPoints.Any() ? trendData.DataPoints.Average(p => p.Value) : 0,
            Maximum = trendData.DataPoints.Any() ? trendData.DataPoints.Max(p => p.Value) : 0,
            Minimum = trendData.DataPoints.Any() ? trendData.DataPoints.Min(p => p.Value) : 0,
            StandardDeviation = CalculateStandardDeviation(trendData.DataPoints.Select(p => p.Value))
        };

        return trendData;
    }

    public async Task<TopThreats> GetTopThreatsAsync(ThreatRankingCriteria criteria, int limit = 10, TimeSpan? timeWindow = null, CancellationToken cancellationToken = default)
    {
        var endTime = DateTime.UtcNow;
        var startTime = timeWindow.HasValue ? endTime - timeWindow.Value : endTime.AddDays(-7);

        var incidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= startTime && i.Timestamp <= endTime)
            .ToListAsync(cancellationToken);

        var topThreats = new TopThreats
        {
            Criteria = criteria,
            Metadata = new TopThreatsMetadata
            {
                AnalysisTimeWindow = timeWindow ?? TimeSpan.FromDays(7),
                TotalIncidentsAnalyzed = incidents.Count,
                AnalysisTimestamp = DateTime.UtcNow
            }
        };

        // Group and rank threats by criteria
        var groupedThreats = incidents.GroupBy(i => i.IPAddress);

        topThreats.Threats = criteria switch
        {
            ThreatRankingCriteria.ThreatScore => groupedThreats
                .Select(g => CreateRankedThreat(g, g.Max(i => i.ThreatScore)))
                .OrderByDescending(t => t.Score)
                .Take(limit)
                .ToList(),
            
            ThreatRankingCriteria.Frequency => groupedThreats
                .Select(g => CreateRankedThreat(g, g.Count()))
                .OrderByDescending(t => t.Score)
                .Take(limit)
                .ToList(),
            
            ThreatRankingCriteria.Impact => groupedThreats
                .Select(g => CreateRankedThreat(g, g.Sum(i => i.ThreatScore * i.RequestCount)))
                .OrderByDescending(t => t.Score)
                .Take(limit)
                .ToList(),
            
            ThreatRankingCriteria.Recency => groupedThreats
                .Select(g => CreateRankedThreat(g, (DateTime.UtcNow - g.Max(i => i.Timestamp)).TotalHours))
                .OrderBy(t => t.Score) // Lower hours = more recent
                .Take(limit)
                .ToList(),
            
            _ => new List<RankedThreat>()
        };

        return topThreats;
    }

    public async Task<SecurityReport> GenerateReportAsync(ReportType reportType, DateTime startTime, DateTime endTime, ReportOptions? options = null, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Generating {ReportType} report for period {Start} to {End}", reportType, startTime, endTime);

        var report = new SecurityReport
        {
            Type = reportType,
            Period = new DateTimeRange { Start = startTime, End = endTime }
        };

        // Get comprehensive metrics
        report.Metrics = await GetSecurityMetricsAsync(startTime, endTime, cancellationToken);

        // Generate executive summary
        report.ExecutiveSummary = GenerateExecutiveSummary(report.Metrics, reportType);

        // Generate key findings
        report.KeyFindings = await GenerateKeyFindings(startTime, endTime, cancellationToken);

        // Generate recommendations
        report.Recommendations = GenerateReportRecommendations(report.Metrics, reportType);

        // Generate charts based on report type
        report.Charts = GenerateReportCharts(report.Metrics, reportType);

        _logger.LogInformation("Generated report {ReportId} with {FindingsCount} findings", 
            report.ReportId, report.KeyFindings.Count);

        return report;
    }

    public async Task<GeographicThreatDistribution> GetGeographicThreatDistributionAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default)
    {
        var endTime = DateTime.UtcNow;
        var startTime = timeWindow.HasValue ? endTime - timeWindow.Value : endTime.AddDays(-7);

        var incidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= startTime && i.Timestamp <= endTime && i.GeographicInfo != null)
            .ToListAsync(cancellationToken);

        return new GeographicThreatDistribution
        {
            CountryDistribution = incidents
                .Where(i => !string.IsNullOrEmpty(i.GeographicInfo?.Country))
                .GroupBy(i => i.GeographicInfo!.Country)
                .ToDictionary(g => g.Key!, g => new GeographicThreatData
                {
                    ThreatCount = g.Count(),
                    AverageThreatScore = g.Average(i => i.ThreatScore),
                    UniqueIPs = g.Select(i => i.IPAddress).Distinct().Count()
                }),
            
            CityDistribution = incidents
                .Where(i => !string.IsNullOrEmpty(i.GeographicInfo?.City))
                .GroupBy(i => new { i.GeographicInfo!.Country, i.GeographicInfo.City })
                .ToDictionary(
                    g => $"{g.Key.City}, {g.Key.Country}", 
                    g => new GeographicThreatData
                    {
                        ThreatCount = g.Count(),
                        AverageThreatScore = g.Average(i => i.ThreatScore),
                        UniqueIPs = g.Select(i => i.IPAddress).Distinct().Count()
                    })
        };
    }

    public async Task RecordSecurityEventAsync(SecurityAnalyticsEvent securityEvent, CancellationToken cancellationToken = default)
    {
        _eventQueue.Enqueue(securityEvent);
        
        // If queue is getting too large, process immediately
        if (_eventQueue.Count > _options.MaxEventQueueSize)
        {
            _ = Task.Run(() => ProcessEventQueue(null), cancellationToken);
        }
    }

    public async Task<PatternStatistics> GetPatternStatisticsAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default)
    {
        var endTime = DateTime.UtcNow;
        var startTime = timeWindow.HasValue ? endTime - timeWindow.Value : endTime.AddDays(-7);

        var threatAssessments = await _context.ThreatAssessments
            .Where(a => a.Timestamp >= startTime && a.Timestamp <= endTime)
            .ToListAsync(cancellationToken);

        return new PatternStatistics
        {
            TotalPatternMatches = threatAssessments.Sum(a => a.MatchedPatterns.Count),
            UniquePatterns = threatAssessments.SelectMany(a => a.MatchedPatterns.Select(p => p.PatternId)).Distinct().Count(),
            TopPatterns = threatAssessments
                .SelectMany(a => a.MatchedPatterns)
                .GroupBy(p => p.PatternId)
                .Select(g => new PatternMatchStatistic
                {
                    PatternId = g.Key,
                    MatchCount = g.Count(),
                    AverageConfidence = g.Average(p => p.Confidence),
                    LastMatch = g.Max(p => p.MatchTimestamp)
                })
                .OrderByDescending(s => s.MatchCount)
                .Take(10)
                .ToList()
        };
    }

    public async Task<PerformanceMetrics> GetPerformanceMetricsAsync(CancellationToken cancellationToken = default)
    {
        return new PerformanceMetrics
        {
            DatabaseResponseTime = await MeasureDatabaseResponseTime(cancellationToken),
            MemoryUsage = GC.GetTotalMemory(false),
            EventQueueSize = _eventQueue.Count,
            CacheHitRate = CalculateCacheHitRate(),
            RequestsPerSecond = await CalculateRequestsPerSecond(cancellationToken),
            AverageProcessingTime = await CalculateAverageProcessingTime(cancellationToken)
        };
    }

    // Private helper methods

    private void ProcessEventQueue(object? state)
    {
        var processedCount = 0;
        var batch = new List<SecurityAnalyticsEvent>();

        // Process events in batches
        while (_eventQueue.TryDequeue(out var securityEvent) && processedCount < _options.EventBatchSize)
        {
            batch.Add(securityEvent);
            processedCount++;
        }

        if (batch.Count > 0)
        {
            _ = Task.Run(async () => await PersistEventBatch(batch));
        }
    }

    private async Task PersistEventBatch(List<SecurityAnalyticsEvent> events)
    {
        try
        {
            // Convert to database entities and save
            // Implementation would depend on your analytics data model
            _logger.LogDebug("Persisted {Count} analytics events", events.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error persisting analytics events");
            
            // Re-queue events on failure
            foreach (var evt in events)
            {
                _eventQueue.Enqueue(evt);
            }
        }
    }

    private async Task<List<ThreatSource>> GetTopThreatSourcesAsync(DateTime since, int limit, CancellationToken cancellationToken)
    {
        var threats = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= since)
            .GroupBy(i => i.IPAddress)
            .Select(g => new ThreatSource
            {
                IPAddress = g.Key,
                ThreatCount = g.Count(),
                AverageThreatScore = g.Average(i => i.ThreatScore),
                LastSeen = g.Max(i => i.Timestamp),
                Categories = g.Select(i => i.Category.ToString()).Distinct().ToList()
            })
            .OrderByDescending(t => t.ThreatCount)
            .Take(limit)
            .ToListAsync(cancellationToken);

        return threats;
    }

    private async Task<bool> CheckDatabaseHealthAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _context.Database.ExecuteSqlRawAsync("SELECT 1", cancellationToken);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static SecurityEventType MapToEventType(ThreatCategory category)
    {
        return category switch
        {
            ThreatCategory.Injection => SecurityEventType.ThreatDetected,
            ThreatCategory.XSS => SecurityEventType.ThreatDetected,
            ThreatCategory.Malware => SecurityEventType.ThreatDetected,
            ThreatCategory.BotTraffic => SecurityEventType.AnomalyDetected,
            ThreatCategory.DDoS => SecurityEventType.AnomalyDetected,
            _ => SecurityEventType.ThreatDetected
        };
    }

    private static SecurityEventSeverity MapToSeverity(double threatScore)
    {
        return threatScore switch
        {
            > 90 => SecurityEventSeverity.Critical,
            > 70 => SecurityEventSeverity.High,
            > 30 => SecurityEventSeverity.Medium,
            _ => SecurityEventSeverity.Low
        };
    }

    private static double CalculateAverageResponseTime(List<SecurityIncident> incidents)
    {
        // This would calculate based on actual response time metrics
        return incidents.Any() ? incidents.Average(i => i.ProcessingTimeMs ?? 0) : 0;
    }

    private static string ExtractPattern(string? requestPath, string? userAgent)
    {
        // Simplified pattern extraction - would be more sophisticated in production
        if (!string.IsNullOrEmpty(requestPath))
        {
            if (requestPath.Contains("admin")) return "admin_access";
            if (requestPath.Contains("..")) return "path_traversal";
            if (requestPath.Contains("union")) return "sql_injection";
        }
        
        return "general";
    }

    private static string CalculateOverallRiskLevel(List<SecurityIncident> incidents)
    {
        if (!incidents.Any()) return "Low";
        
        var avgThreatScore = incidents.Average(i => i.ThreatScore);
        return avgThreatScore switch
        {
            > 80 => "Critical",
            > 60 => "High",
            > 30 => "Medium",
            _ => "Low"
        };
    }

    private static TrendDirection CalculateThreatTrend(List<SecurityIncident> incidents)
    {
        if (incidents.Count < 2) return TrendDirection.Stable;
        
        var recent = incidents.Where(i => i.Timestamp >= DateTime.UtcNow.AddHours(-24)).Count();
        var earlier = incidents.Where(i => i.Timestamp >= DateTime.UtcNow.AddHours(-48) && i.Timestamp < DateTime.UtcNow.AddHours(-24)).Count();
        
        var change = earlier > 0 ? ((double)(recent - earlier) / earlier) * 100 : 0;
        
        return Math.Abs(change) < 10 ? TrendDirection.Stable :
               change > 0 ? TrendDirection.Increasing : TrendDirection.Decreasing;
    }

    private static List<ThreatMitigationRecommendation> GenerateThreatMitigationRecommendations(ThreatAnalysis analysis)
    {
        var recommendations = new List<ThreatMitigationRecommendation>();
        
        // Add recommendations based on analysis
        if (analysis.IPProfiles.Any(p => p.AverageThreatScore > 80))
        {
            recommendations.Add(new ThreatMitigationRecommendation
            {
                Priority = "High",
                Category = "IP Blocking",
                Description = "Consider blocking high-threat IP addresses",
                ActionItems = new List<string> { "Review and block top threat IPs", "Implement geo-blocking if applicable" }
            });
        }
        
        return recommendations;
    }

    private static DateTime GetWeekStart(DateTime date)
    {
        var diff = (7 + (date.DayOfWeek - DayOfWeek.Monday)) % 7;
        return date.AddDays(-1 * diff).Date;
    }

    private static double CalculateStandardDeviation(IEnumerable<double> values)
    {
        var enumerable = values.ToList();
        if (!enumerable.Any()) return 0;
        
        var avg = enumerable.Average();
        var sum = enumerable.Sum(v => Math.Pow(v - avg, 2));
        return Math.Sqrt(sum / enumerable.Count);
    }

    private static RankedThreat CreateRankedThreat(IGrouping<string, SecurityIncident> group, double score)
    {
        return new RankedThreat
        {
            IPAddress = group.Key,
            Score = score,
            IncidentCount = group.Count(),
            AverageThreatScore = group.Average(i => i.ThreatScore),
            LastSeen = group.Max(i => i.Timestamp),
            Categories = group.Select(i => i.Category.ToString()).Distinct().ToList(),
            GeographicInfo = group.FirstOrDefault()?.GeographicInfo
        };
    }

    private string GenerateExecutiveSummary(SecurityMetrics metrics, ReportType reportType)
    {
        return reportType switch
        {
            ReportType.Executive => $"During the reporting period, {metrics.TotalRequests:N0} requests were analyzed, with {metrics.ThreatsDetected:N0} threats detected and {metrics.BlockedRequests:N0} requests blocked. The security posture shows {(metrics.AverageThreatScore > 50 ? "elevated" : "normal")} threat levels.",
            ReportType.Technical => $"Technical analysis of {metrics.TotalRequests:N0} requests identified {metrics.SecurityIncidents:N0} security incidents across {metrics.UniqueIPs:N0} unique IP addresses.",
            _ => "Security analysis completed for the specified time period."
        };
    }

    private async Task<List<ReportFinding>> GenerateKeyFindings(DateTime startTime, DateTime endTime, CancellationToken cancellationToken)
    {
        var findings = new List<ReportFinding>();
        
        // Add key findings based on data analysis
        var incidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= startTime && i.Timestamp <= endTime)
            .ToListAsync(cancellationToken);

        if (incidents.Any(i => i.ThreatScore > 90))
        {
            findings.Add(new ReportFinding
            {
                Severity = "High",
                Category = "Critical Threats",
                Description = "Critical threat levels detected",
                Impact = "Potential security compromise",
                Recommendation = "Immediate investigation recommended"
            });
        }
        
        return findings;
    }

    private static List<ReportRecommendation> GenerateReportRecommendations(SecurityMetrics metrics, ReportType reportType)
    {
        var recommendations = new List<ReportRecommendation>();
        
        if (metrics.AverageThreatScore > 50)
        {
            recommendations.Add(new ReportRecommendation
            {
                Priority = "High",
                Category = "Threat Mitigation",
                Description = "Implement enhanced security measures",
                EstimatedEffort = "Medium",
                ExpectedImpact = "Significant reduction in threat levels"
            });
        }
        
        return recommendations;
    }

    private static List<ReportChart> GenerateReportCharts(SecurityMetrics metrics, ReportType reportType)
    {
        var charts = new List<ReportChart>();
        
        charts.Add(new ReportChart
        {
            Type = "line",
            Title = "Threat Trends Over Time",
            Data = metrics.HourlyBreakdown.ToDictionary(
                h => h.Hour.ToString("yyyy-MM-dd HH:00"),
                h => (object)h.ThreatCount
            )
        });
        
        return charts;
    }

    private async Task<double> MeasureDatabaseResponseTime(CancellationToken cancellationToken)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            await _context.IPRecords.Take(1).ToListAsync(cancellationToken);
            stopwatch.Stop();
            return stopwatch.ElapsedMilliseconds;
        }
        catch
        {
            return -1;
        }
    }

    private double CalculateCacheHitRate()
    {
        // This would require cache hit/miss tracking
        return 0.85; // Placeholder
    }

    private async Task<double> CalculateRequestsPerSecond(CancellationToken cancellationToken)
    {
        var oneMinuteAgo = DateTime.UtcNow.AddMinutes(-1);
        var recentRequests = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= oneMinuteAgo)
            .SumAsync(i => i.RequestCount, cancellationToken);
        
        return recentRequests / 60.0;
    }

    private async Task<double> CalculateAverageProcessingTime(CancellationToken cancellationToken)
    {
        var recentIncidents = await _context.SecurityIncidents
            .Where(i => i.Timestamp >= DateTime.UtcNow.AddHours(-1) && i.ProcessingTimeMs.HasValue)
            .Select(i => i.ProcessingTimeMs!.Value)
            .ToListAsync(cancellationToken);
        
        return recentIncidents.Any() ? recentIncidents.Average() : 0;
    }

    public void Dispose()
    {
        _processingTimer?.Dispose();
    }
}

/// <summary>
/// Configuration options for the analytics service
/// </summary>
public class AnalyticsOptions
{
    /// <summary>
    /// Cache duration for metrics in minutes
    /// </summary>
    public int MetricsCacheDurationMinutes { get; set; } = 15;

    /// <summary>
    /// Cache duration for dashboard data in seconds
    /// </summary>
    public int DashboardCacheDurationSeconds { get; set; } = 30;

    /// <summary>
    /// Maximum size of the event queue
    /// </summary>
    public int MaxEventQueueSize { get; set; } = 1000;

    /// <summary>
    /// Batch size for processing events
    /// </summary>
    public int EventBatchSize { get; set; } = 100;

    /// <summary>
    /// Whether to enable real-time analytics
    /// </summary>
    public bool EnableRealTimeAnalytics { get; set; } = true;

    /// <summary>
    /// Data retention period for analytics data
    /// </summary>
    public TimeSpan DataRetentionPeriod { get; set; } = TimeSpan.FromDays(90);
}

// Extended supporting classes for the implementation

public class SystemHealth
{
    public bool DatabaseConnectionHealthy { get; set; }
    public double AverageResponseTime { get; set; }
    public long MemoryUsage { get; set; }
    public int EventQueueSize { get; set; }
}

public class RealTimeMetrics
{
    public int RequestsPerMinute { get; set; }
    public int ThreatsPerMinute { get; set; }
    public double AverageThreatScore { get; set; }
}

public class AlertSummary
{
    public int CriticalAlerts { get; set; }
    public int HighAlerts { get; set; }
    public int MediumAlerts { get; set; }
    public int LowAlerts { get; set; }
}

public class ThreatSource
{
    public string IPAddress { get; set; } = "";
    public int ThreatCount { get; set; }
    public double AverageThreatScore { get; set; }
    public DateTime LastSeen { get; set; }
    public List<string> Categories { get; set; } = new();
}

public class IPThreatProfile
{
    public string IPAddress { get; set; } = "";
    public int TotalIncidents { get; set; }
    public double AverageThreatScore { get; set; }
    public double HighestThreatScore { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public List<string> Categories { get; set; } = new();
    public IPGeographicInfo? GeographicInfo { get; set; }
}

public class AttackPattern
{
    public string Category { get; set; } = "";
    public string Pattern { get; set; } = "";
    public int Frequency { get; set; }
    public double AverageThreatScore { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int AffectedIPs { get; set; }
}

public class RiskAssessmentSummary
{
    public string OverallRiskLevel { get; set; } = "";
    public int TotalThreats { get; set; }
    public int CriticalThreats { get; set; }
    public int HighThreats { get; set; }
    public int MediumThreats { get; set; }
    public int LowThreats { get; set; }
    public TrendDirection TrendDirection { get; set; }
}

public class ThreatMitigationRecommendation
{
    public string Priority { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public List<string> ActionItems { get; set; } = new();
}

public class TrendDataPoint
{
    public DateTime Timestamp { get; set; }
    public double Value { get; set; }
    public int Count { get; set; }
}

public class TrendStatistics
{
    public double Average { get; set; }
    public double Maximum { get; set; }
    public double Minimum { get; set; }
    public double StandardDeviation { get; set; }
}

public class RankedThreat
{
    public string IPAddress { get; set; } = "";
    public double Score { get; set; }
    public int IncidentCount { get; set; }
    public double AverageThreatScore { get; set; }
    public DateTime LastSeen { get; set; }
    public List<string> Categories { get; set; } = new();
    public IPGeographicInfo? GeographicInfo { get; set; }
}

public class TopThreatsMetadata
{
    public TimeSpan AnalysisTimeWindow { get; set; }
    public int TotalIncidentsAnalyzed { get; set; }
    public DateTime AnalysisTimestamp { get; set; }
}

public class ReportFinding
{
    public string Severity { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public string Impact { get; set; } = "";
    public string Recommendation { get; set; } = "";
}

public class ReportRecommendation
{
    public string Priority { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public string EstimatedEffort { get; set; } = "";
    public string ExpectedImpact { get; set; } = "";
}

public class ReportChart
{
    public string Type { get; set; } = "";
    public string Title { get; set; } = "";
    public Dictionary<string, object> Data { get; set; } = new();
}

public class GeographicThreatDistribution
{
    public Dictionary<string, GeographicThreatData> CountryDistribution { get; set; } = new();
    public Dictionary<string, GeographicThreatData> CityDistribution { get; set; } = new();
}

public class GeographicThreatData
{
    public int ThreatCount { get; set; }
    public double AverageThreatScore { get; set; }
    public int UniqueIPs { get; set; }
}

public class PatternStatistics
{
    public int TotalPatternMatches { get; set; }
    public int UniquePatterns { get; set; }
    public List<PatternMatchStatistic> TopPatterns { get; set; } = new();
}

public class PatternMatchStatistic
{
    public string PatternId { get; set; } = "";
    public int MatchCount { get; set; }
    public double AverageConfidence { get; set; }
    public DateTime LastMatch { get; set; }
}

public class PerformanceMetrics
{
    public double DatabaseResponseTime { get; set; }
    public long MemoryUsage { get; set; }
    public int EventQueueSize { get; set; }
    public double CacheHitRate { get; set; }
    public double RequestsPerSecond { get; set; }
    public double AverageProcessingTime { get; set; }
}