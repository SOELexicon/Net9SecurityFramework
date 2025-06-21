namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Service for managing IP blocklists from multiple sources
/// </summary>
public interface IBlocklistService
{
    /// <summary>
    /// Checks if an IP address is blocked by any source
    /// </summary>
    /// <param name="ipAddress">IP address to check</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Blocklist result with details</returns>
    Task<BlocklistResult> IsBlockedAsync(string ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if an IP address is blocked by any source (synchronous)
    /// </summary>
    /// <param name="ipAddress">IP address to check</param>
    /// <returns>Blocklist result with details</returns>
    BlocklistResult IsBlocked(string ipAddress);

    /// <summary>
    /// Adds an IP address to the local blocklist
    /// </summary>
    /// <param name="ipAddress">IP address to block</param>
    /// <param name="reason">Reason for blocking</param>
    /// <param name="expiresAt">Optional expiration time</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task AddToBlocklistAsync(string ipAddress, string reason, DateTime? expiresAt = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an IP address from the local blocklist
    /// </summary>
    /// <param name="ipAddress">IP address to unblock</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task RemoveFromBlocklistAsync(string ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds an IP range to the local blocklist
    /// </summary>
    /// <param name="cidrRange">CIDR range to block</param>
    /// <param name="reason">Reason for blocking</param>
    /// <param name="expiresAt">Optional expiration time</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task AddRangeToBlocklistAsync(string cidrRange, string reason, DateTime? expiresAt = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an IP range from the local blocklist
    /// </summary>
    /// <param name="cidrRange">CIDR range to unblock</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task RemoveRangeFromBlocklistAsync(string cidrRange, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets statistics about blocklist sources and performance
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Blocklist statistics</returns>
    Task<BlocklistStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Refreshes blocklists from external sources
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task RefreshBlocklistsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all active blocklist entries
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Collection of blocklist entries</returns>
    Task<IEnumerable<BlocklistEntry>> GetBlocklistEntriesAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a blocklist check
/// </summary>
public class BlocklistResult
{
    /// <summary>
    /// Whether the IP address is blocked
    /// </summary>
    public bool IsBlocked { get; set; }

    /// <summary>
    /// Reason for blocking
    /// </summary>
    public string? Reason { get; set; }

    /// <summary>
    /// Source that reported the block
    /// </summary>
    public string? Source { get; set; }

    /// <summary>
    /// Confidence level of the block (0-100)
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Categories associated with the block
    /// </summary>
    public List<string> Categories { get; set; } = new();

    /// <summary>
    /// When the block was first detected
    /// </summary>
    public DateTime? FirstSeen { get; set; }

    /// <summary>
    /// When the block was last updated
    /// </summary>
    public DateTime? LastSeen { get; set; }

    /// <summary>
    /// Additional metadata about the block
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Statistics about blocklist performance
/// </summary>
public class BlocklistStatistics
{
    /// <summary>
    /// Total number of blocked IPs
    /// </summary>
    public long TotalBlockedIPs { get; set; }

    /// <summary>
    /// Total number of blocked ranges
    /// </summary>
    public long TotalBlockedRanges { get; set; }

    /// <summary>
    /// Number of active blocklist sources
    /// </summary>
    public int ActiveSources { get; set; }

    /// <summary>
    /// Last update time for blocklists
    /// </summary>
    public DateTime LastUpdate { get; set; }

    /// <summary>
    /// Average response time for blocklist checks (ms)
    /// </summary>
    public double AverageResponseTime { get; set; }

    /// <summary>
    /// Number of blocklist checks performed today
    /// </summary>
    public long ChecksToday { get; set; }

    /// <summary>
    /// Number of blocks detected today
    /// </summary>
    public long BlocksToday { get; set; }

    /// <summary>
    /// Statistics by source
    /// </summary>
    public Dictionary<string, BlocklistSourceStatistics> SourceStatistics { get; set; } = new();
}

/// <summary>
/// Statistics for a specific blocklist source
/// </summary>
public class BlocklistSourceStatistics
{
    /// <summary>
    /// Source name
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Whether the source is active
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Number of entries from this source
    /// </summary>
    public long EntryCount { get; set; }

    /// <summary>
    /// Last successful update
    /// </summary>
    public DateTime? LastUpdate { get; set; }

    /// <summary>
    /// Last error message (if any)
    /// </summary>
    public string? LastError { get; set; }

    /// <summary>
    /// Average response time for this source (ms)
    /// </summary>
    public double AverageResponseTime { get; set; }

    /// <summary>
    /// Success rate for this source (0-100)
    /// </summary>
    public double SuccessRate { get; set; }
}

/// <summary>
/// Represents a blocklist entry
/// </summary>
public class BlocklistEntry
{
    /// <summary>
    /// Unique identifier for the entry
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// IP address or CIDR range
    /// </summary>
    public string IPOrRange { get; set; } = "";

    /// <summary>
    /// Type of entry (IP or Range)
    /// </summary>
    public BlocklistEntryType Type { get; set; }

    /// <summary>
    /// Source that provided this entry
    /// </summary>
    public string Source { get; set; } = "";

    /// <summary>
    /// Reason for blocking
    /// </summary>
    public string Reason { get; set; } = "";

    /// <summary>
    /// Categories associated with this entry
    /// </summary>
    public List<string> Categories { get; set; } = new();

    /// <summary>
    /// Confidence level (0-100)
    /// </summary>
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// When this entry was first added
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When this entry was last updated
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When this entry expires (if applicable)
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Whether this entry is currently active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Type of blocklist entry
/// </summary>
public enum BlocklistEntryType
{
    /// <summary>
    /// Single IP address
    /// </summary>
    IP,

    /// <summary>
    /// IP range in CIDR notation
    /// </summary>
    Range
}