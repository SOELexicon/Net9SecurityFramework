namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Service for security analytics and reporting
/// </summary>
public interface IAnalyticsService
{
    /// <summary>
    /// Gets security metrics for a specific time period
    /// </summary>
    /// <param name="startTime">Start of the time period</param>
    /// <param name="endTime">End of the time period</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Security metrics</returns>
    Task<SecurityMetrics> GetSecurityMetricsAsync(DateTime startTime, DateTime endTime, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets real-time security dashboard data
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Dashboard data</returns>
    Task<SecurityDashboard> GetDashboardDataAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets threat analysis for IP addresses
    /// </summary>
    /// <param name="ipAddress">IP address to analyze (optional)</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Threat analysis results</returns>
    Task<ThreatAnalysis> GetThreatAnalysisAsync(string? ipAddress = null, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets security trend data
    /// </summary>
    /// <param name="metric">Metric to analyze</param>
    /// <param name="period">Time period for the trend</param>
    /// <param name="granularity">Data granularity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Trend data</returns>
    Task<TrendData> GetTrendDataAsync(SecurityMetricType metric, TimeSpan period, TrendGranularity granularity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets top threats by various criteria
    /// </summary>
    /// <param name="criteria">Criteria for ranking threats</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="timeWindow">Time window for analysis</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Top threats</returns>
    Task<TopThreats> GetTopThreatsAsync(ThreatRankingCriteria criteria, int limit = 10, TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a security report
    /// </summary>
    /// <param name="reportType">Type of report to generate</param>
    /// <param name="startTime">Start of the reporting period</param>
    /// <param name="endTime">End of the reporting period</param>
    /// <param name="options">Report generation options</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Generated report</returns>
    Task<SecurityReport> GenerateReportAsync(ReportType reportType, DateTime startTime, DateTime endTime, ReportOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets geographic distribution of threats
    /// </summary>
    /// <param name="timeWindow">Time window for analysis</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Geographic threat distribution</returns>
    Task<GeographicThreatDistribution> GetGeographicThreatDistributionAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a security event for analytics
    /// </summary>
    /// <param name="securityEvent">Security event to record</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task RecordSecurityEventAsync(SecurityAnalyticsEvent securityEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets pattern matching statistics
    /// </summary>
    /// <param name="timeWindow">Time window for analysis</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pattern statistics</returns>
    Task<PatternStatistics> GetPatternStatisticsAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets performance metrics for the security framework
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Performance metrics</returns>
    Task<PerformanceMetrics> GetPerformanceMetricsAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Security metrics for a time period
/// </summary>
public class SecurityMetrics
{
    /// <summary>
    /// Total number of requests analyzed
    /// </summary>
    public long TotalRequests { get; set; }

    /// <summary>
    /// Number of threats detected
    /// </summary>
    public long ThreatsDetected { get; set; }

    /// <summary>
    /// Number of blocked requests
    /// </summary>
    public long BlockedRequests { get; set; }

    /// <summary>
    /// Unique IP addresses seen
    /// </summary>
    public long UniqueIPs { get; set; }

    /// <summary>
    /// Number of security incidents
    /// </summary>
    public long SecurityIncidents { get; set; }

    /// <summary>
    /// Parameter security violations
    /// </summary>
    public long ParameterViolations { get; set; }

    /// <summary>
    /// Average threat score
    /// </summary>
    public double AverageThreatScore { get; set; }

    /// <summary>
    /// Highest threat score recorded
    /// </summary>
    public double HighestThreatScore { get; set; }

    /// <summary>
    /// Time period for these metrics
    /// </summary>
    public DateTimeRange TimePeriod { get; set; } = new();

    /// <summary>
    /// Metrics by category
    /// </summary>
    public Dictionary<string, long> MetricsByCategory { get; set; } = new();

    /// <summary>
    /// Hourly breakdown of metrics
    /// </summary>
    public List<HourlyMetrics> HourlyBreakdown { get; set; } = new();
}

/// <summary>
/// Real-time security dashboard data
/// </summary>
public class SecurityDashboard
{
    /// <summary>
    /// Current security status
    /// </summary>
    public SecurityStatus Status { get; set; }

    /// <summary>
    /// Active threats count
    /// </summary>
    public int ActiveThreats { get; set; }

    /// <summary>
    /// Requests in the last hour
    /// </summary>
    public long RequestsLastHour { get; set; }

    /// <summary>
    /// Blocked requests in the last hour
    /// </summary>
    public long BlockedLastHour { get; set; }

    /// <summary>
    /// Recent security events
    /// </summary>
    public List<SecurityAnalyticsEvent> RecentEvents { get; set; } = new();

    /// <summary>
    /// Top threat sources
    /// </summary>
    public List<ThreatSource> TopThreatSources { get; set; } = new();

    /// <summary>
    /// System health indicators
    /// </summary>
    public SystemHealth SystemHealth { get; set; } = new();

    /// <summary>
    /// Real-time metrics
    /// </summary>
    public RealTimeMetrics RealTimeMetrics { get; set; } = new();

    /// <summary>
    /// Alert summary
    /// </summary>
    public AlertSummary Alerts { get; set; } = new();
}

/// <summary>
/// Threat analysis results
/// </summary>
public class ThreatAnalysis
{
    /// <summary>
    /// IP addresses analyzed
    /// </summary>
    public List<IPThreatProfile> IPProfiles { get; set; } = new();

    /// <summary>
    /// Attack patterns detected
    /// </summary>
    public List<AttackPattern> AttackPatterns { get; set; } = new();

    /// <summary>
    /// Risk assessment summary
    /// </summary>
    public RiskAssessmentSummary RiskSummary { get; set; } = new();

    /// <summary>
    /// Recommendations for threat mitigation
    /// </summary>
    public List<ThreatMitigationRecommendation> Recommendations { get; set; } = new();
}

/// <summary>
/// Trend data for security metrics
/// </summary>
public class TrendData
{
    /// <summary>
    /// Metric being analyzed
    /// </summary>
    public SecurityMetricType Metric { get; set; }

    /// <summary>
    /// Data points over time
    /// </summary>
    public List<TrendDataPoint> DataPoints { get; set; } = new();

    /// <summary>
    /// Trend direction
    /// </summary>
    public TrendDirection Direction { get; set; }

    /// <summary>
    /// Change percentage from previous period
    /// </summary>
    public double ChangePercentage { get; set; }

    /// <summary>
    /// Statistical analysis
    /// </summary>
    public TrendStatistics Statistics { get; set; } = new();
}

/// <summary>
/// Top threats analysis
/// </summary>
public class TopThreats
{
    /// <summary>
    /// Ranking criteria used
    /// </summary>
    public ThreatRankingCriteria Criteria { get; set; }

    /// <summary>
    /// Ranked threat entries
    /// </summary>
    public List<RankedThreat> Threats { get; set; } = new();

    /// <summary>
    /// Analysis metadata
    /// </summary>
    public TopThreatsMetadata Metadata { get; set; } = new();
}

/// <summary>
/// Generated security report
/// </summary>
public class SecurityReport
{
    /// <summary>
    /// Report unique identifier
    /// </summary>
    public string ReportId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Report type
    /// </summary>
    public ReportType Type { get; set; }

    /// <summary>
    /// Generation timestamp
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Reporting period
    /// </summary>
    public DateTimeRange Period { get; set; } = new();

    /// <summary>
    /// Executive summary
    /// </summary>
    public string ExecutiveSummary { get; set; } = "";

    /// <summary>
    /// Detailed metrics
    /// </summary>
    public SecurityMetrics Metrics { get; set; } = new();

    /// <summary>
    /// Key findings
    /// </summary>
    public List<ReportFinding> KeyFindings { get; set; } = new();

    /// <summary>
    /// Recommendations
    /// </summary>
    public List<ReportRecommendation> Recommendations { get; set; } = new();

    /// <summary>
    /// Supporting charts and graphs
    /// </summary>
    public List<ReportChart> Charts { get; set; } = new();

    /// <summary>
    /// Raw data used for the report
    /// </summary>
    public Dictionary<string, object> RawData { get; set; } = new();
}

/// <summary>
/// Security analytics event
/// </summary>
public class SecurityAnalyticsEvent
{
    /// <summary>
    /// Event unique identifier
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Event timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Event type
    /// </summary>
    public SecurityEventType Type { get; set; }

    /// <summary>
    /// Event severity
    /// </summary>
    public SecurityEventSeverity Severity { get; set; }

    /// <summary>
    /// Source IP address
    /// </summary>
    public string? IPAddress { get; set; }

    /// <summary>
    /// User agent
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Request path
    /// </summary>
    public string? RequestPath { get; set; }

    /// <summary>
    /// HTTP method
    /// </summary>
    public string? HttpMethod { get; set; }

    /// <summary>
    /// Threat score
    /// </summary>
    public double ThreatScore { get; set; }

    /// <summary>
    /// Event description
    /// </summary>
    public string Description { get; set; } = "";

    /// <summary>
    /// Categories
    /// </summary>
    public List<string> Categories { get; set; } = new();

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

// Supporting classes and enums

public class DateTimeRange
{
    public DateTime Start { get; set; }
    public DateTime End { get; set; }
}

public class HourlyMetrics
{
    public DateTime Hour { get; set; }
    public long RequestCount { get; set; }
    public long ThreatCount { get; set; }
    public long BlockedCount { get; set; }
    public double AverageThreatScore { get; set; }
}

public enum SecurityStatus
{
    Normal,
    Elevated,
    High,
    Critical
}

public enum SecurityMetricType
{
    TotalRequests,
    ThreatsDetected,
    BlockedRequests,
    UniqueIPs,
    SecurityIncidents,
    ParameterViolations,
    AverageThreatScore
}

public enum TrendGranularity
{
    Hourly,
    Daily,
    Weekly,
    Monthly
}

public enum ThreatRankingCriteria
{
    ThreatScore,
    Frequency,
    Impact,
    Recency
}

public enum ReportType
{
    Executive,
    Technical,
    Compliance,
    Incident
}

public enum SecurityEventType
{
    ThreatDetected,
    RequestBlocked,
    ParameterViolation,
    PatternMatch,
    AnomalyDetected
}

public enum SecurityEventSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public enum TrendDirection
{
    Increasing,
    Decreasing,
    Stable,
    Volatile
}

// Additional supporting classes would be defined here for complete implementation
public class ThreatSource { }
public class SystemHealth { }
public class RealTimeMetrics { }
public class AlertSummary { }
public class IPThreatProfile { }
public class AttackPattern { }
public class RiskAssessmentSummary { }
public class ThreatMitigationRecommendation { }
public class TrendDataPoint { }
public class TrendStatistics { }
public class RankedThreat { }
public class TopThreatsMetadata { }
public class ReportFinding { }
public class ReportRecommendation { }
public class ReportChart { }
public class ReportOptions { }
public class GeographicThreatDistribution { }
public class PatternStatistics { }
public class PerformanceMetrics { }