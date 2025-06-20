using SecurityFramework.Core.Models;

namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Core security service interface for threat assessment and IP tracking
/// </summary>
public interface ISecurityService
{
    /// <summary>
    /// Assesses the threat level of an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to assess</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Threat assessment result</returns>
    Task<ThreatAssessment> AssessIPAsync(string ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Assesses the threat level of an IP address with additional context
    /// </summary>
    /// <param name="ipAddress">The IP address to assess</param>
    /// <param name="context">Additional context for assessment</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Threat assessment result</returns>
    Task<ThreatAssessment> AssessIPAsync(string ipAddress, ThreatContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets detailed information about an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to lookup</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>IP record if found, null otherwise</returns>
    Task<IPRecord?> GetIPRecordAsync(string ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the threat score for an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to update</param>
    /// <param name="threatScore">New threat score (0-100)</param>
    /// <param name="reason">Reason for the update</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> UpdateThreatScoreAsync(string ipAddress, double threatScore, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the trust score for an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to update</param>
    /// <param name="trustScore">New trust score (0-100)</param>
    /// <param name="reason">Reason for the update</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> UpdateTrustScoreAsync(string ipAddress, double trustScore, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Blocks an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to block</param>
    /// <param name="reason">Reason for blocking</param>
    /// <param name="expiresAt">When the block expires (null for permanent)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> BlockIPAsync(string ipAddress, string reason, DateTime? expiresAt = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Unblocks an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to unblock</param>
    /// <param name="reason">Reason for unblocking</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> UnblockIPAsync(string ipAddress, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a request from an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address making the request</param>
    /// <param name="userAgent">User agent string</param>
    /// <param name="requestPath">Request path</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> RecordRequestAsync(string ipAddress, string? userAgent = null, string? requestPath = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a blocked request from an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address that was blocked</param>
    /// <param name="reason">Reason for blocking the request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated IP record</returns>
    Task<IPRecord> RecordBlockedRequestAsync(string ipAddress, string reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets IP addresses with threat scores above a threshold
    /// </summary>
    /// <param name="threshold">Minimum threat score</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of high-threat IP addresses</returns>
    Task<List<IPRecord>> GetHighThreatIPsAsync(double threshold = 80.0, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets blocked IP addresses
    /// </summary>
    /// <param name="includeExpired">Whether to include expired blocks</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of blocked IP addresses</returns>
    Task<List<IPRecord>> GetBlockedIPsAsync(bool includeExpired = false, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets security statistics for a time period
    /// </summary>
    /// <param name="fromDate">Start date</param>
    /// <param name="toDate">End date</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Security statistics</returns>
    Task<SecurityStatistics> GetStatisticsAsync(DateTime fromDate, DateTime toDate, CancellationToken cancellationToken = default);

    /// <summary>
    /// Cleans up expired blocks and old records
    /// </summary>
    /// <param name="retentionDays">How many days to keep records</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Number of records cleaned up</returns>
    Task<int> CleanupAsync(int retentionDays = 90, CancellationToken cancellationToken = default);
}

/// <summary>
/// Security statistics for a time period
/// </summary>
public class SecurityStatistics
{
    /// <summary>
    /// Total number of requests assessed
    /// </summary>
    public long TotalRequests { get; set; }

    /// <summary>
    /// Number of requests blocked
    /// </summary>
    public long BlockedRequests { get; set; }

    /// <summary>
    /// Number of unique IP addresses seen
    /// </summary>
    public long UniqueIPAddresses { get; set; }

    /// <summary>
    /// Number of high-threat IP addresses
    /// </summary>
    public long HighThreatIPs { get; set; }

    /// <summary>
    /// Average threat score
    /// </summary>
    public double AverageThreatScore { get; set; }

    /// <summary>
    /// Average trust score
    /// </summary>
    public double AverageTrustScore { get; set; }

    /// <summary>
    /// Top threat categories
    /// </summary>
    public Dictionary<string, long> TopThreatCategories { get; set; } = new();

    /// <summary>
    /// Top blocked reasons
    /// </summary>
    public Dictionary<string, long> TopBlockReasons { get; set; } = new();

    /// <summary>
    /// Geographic distribution of threats
    /// </summary>
    public Dictionary<string, long> GeographicDistribution { get; set; } = new();

    /// <summary>
    /// Time period for these statistics
    /// </summary>
    public DateTimeOffset StartTime { get; set; }

    /// <summary>
    /// End time for these statistics
    /// </summary>
    public DateTimeOffset EndTime { get; set; }

    /// <summary>
    /// When these statistics were generated
    /// </summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
}