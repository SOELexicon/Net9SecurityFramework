using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecurityFramework.Core.Models;

/// <summary>
/// Represents an IP address record with threat intelligence and behavioral data
/// </summary>
public class IPRecord
{
    /// <summary>
    /// Unique identifier for the IP record
    /// </summary>
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// The IP address (IPv4 or IPv6)
    /// </summary>
    [Required]
    [StringLength(45)] // IPv6 max length
    [Index]
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// Trust score ranging from 0 (untrusted) to 100 (highly trusted)
    /// </summary>
    [Range(0, 100)]
    public double TrustScore { get; set; } = 50.0;

    /// <summary>
    /// Threat score ranging from 0 (no threat) to 100 (high threat)
    /// </summary>
    [Range(0, 100)]
    public double ThreatScore { get; set; } = 0.0;

    /// <summary>
    /// First time this IP was observed
    /// </summary>
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Last time this IP was observed
    /// </summary>
    [Index]
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Total number of requests from this IP
    /// </summary>
    public long RequestCount { get; set; } = 0;

    /// <summary>
    /// Number of blocked requests from this IP
    /// </summary>
    public long BlockedCount { get; set; } = 0;

    /// <summary>
    /// Whether this IP is currently blocked
    /// </summary>
    public bool IsBlocked { get; set; } = false;

    /// <summary>
    /// When the IP was blocked (if blocked)
    /// </summary>
    public DateTime? BlockedAt { get; set; }

    /// <summary>
    /// Reason for blocking
    /// </summary>
    [StringLength(500)]
    public string? BlockReason { get; set; }

    /// <summary>
    /// When the block expires (null for permanent blocks)
    /// </summary>
    public DateTime? BlockExpiresAt { get; set; }

    /// <summary>
    /// Geographic information for this IP
    /// </summary>
    public IPGeographicInfo? GeographicInfo { get; set; }

    /// <summary>
    /// Behavioral profile for this IP
    /// </summary>
    public IPBehaviorProfile? BehaviorProfile { get; set; }

    /// <summary>
    /// Categories this IP belongs to (bot, proxy, tor, etc.)
    /// </summary>
    public List<IPCategory> Categories { get; set; } = new();

    /// <summary>
    /// Additional flags for this IP
    /// </summary>
    public List<string> Flags { get; set; } = new();

    /// <summary>
    /// Metadata as JSON
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// Record creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Record last update timestamp
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Version for optimistic concurrency
    /// </summary>
    [Timestamp]
    public byte[] Version { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Updates the last seen timestamp and increments request count
    /// </summary>
    public void RecordRequest()
    {
        LastSeen = DateTime.UtcNow;
        RequestCount++;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Records a blocked request
    /// </summary>
    public void RecordBlockedRequest(string reason)
    {
        RecordRequest();
        BlockedCount++;
        
        if (!IsBlocked)
        {
            IsBlocked = true;
            BlockedAt = DateTime.UtcNow;
            BlockReason = reason;
        }
    }

    /// <summary>
    /// Unblocks the IP address
    /// </summary>
    public void Unblock()
    {
        IsBlocked = false;
        BlockedAt = null;
        BlockReason = null;
        BlockExpiresAt = null;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Checks if the IP block has expired
    /// </summary>
    public bool IsBlockExpired()
    {
        return IsBlocked && 
               BlockExpiresAt.HasValue && 
               DateTime.UtcNow > BlockExpiresAt.Value;
    }

    /// <summary>
    /// Calculates a combined risk score based on trust and threat scores
    /// </summary>
    public double CalculateRiskScore()
    {
        // Risk score is inverse of trust score plus threat score, normalized
        var risk = (100 - TrustScore) + ThreatScore;
        return Math.Min(risk / 2, 100);
    }
}

/// <summary>
/// Geographic information for an IP address
/// </summary>
public class IPGeographicInfo
{
    /// <summary>
    /// Country code (ISO 3166-1 alpha-2)
    /// </summary>
    [StringLength(2)]
    public string? CountryCode { get; set; }

    /// <summary>
    /// Country name
    /// </summary>
    [StringLength(100)]
    public string? CountryName { get; set; }

    /// <summary>
    /// Region or state
    /// </summary>
    [StringLength(100)]
    public string? Region { get; set; }

    /// <summary>
    /// City name
    /// </summary>
    [StringLength(100)]
    public string? City { get; set; }

    /// <summary>
    /// Latitude
    /// </summary>
    public double? Latitude { get; set; }

    /// <summary>
    /// Longitude
    /// </summary>
    public double? Longitude { get; set; }

    /// <summary>
    /// Time zone identifier
    /// </summary>
    [StringLength(50)]
    public string? TimeZone { get; set; }

    /// <summary>
    /// Internet Service Provider
    /// </summary>
    [StringLength(200)]
    public string? ISP { get; set; }

    /// <summary>
    /// Organization name
    /// </summary>
    [StringLength(200)]
    public string? Organization { get; set; }

    /// <summary>
    /// Autonomous System Number
    /// </summary>
    public int? ASN { get; set; }

    /// <summary>
    /// Whether this is a known high-risk location
    /// </summary>
    public bool IsHighRiskLocation { get; set; } = false;
}

/// <summary>
/// Behavioral profile for an IP address
/// </summary>
public class IPBehaviorProfile
{
    /// <summary>
    /// Average requests per hour
    /// </summary>
    public double RequestFrequency { get; set; } = 0.0;

    /// <summary>
    /// Average session duration in minutes
    /// </summary>
    public double AverageSessionDuration { get; set; } = 0.0;

    /// <summary>
    /// Number of unique User-Agent strings observed
    /// </summary>
    public int UserAgentVariations { get; set; } = 0;

    /// <summary>
    /// Geographic consistency score (0-1, 1 being most consistent)
    /// </summary>
    public double GeographicConsistency { get; set; } = 1.0;

    /// <summary>
    /// Time pattern consistency score (0-1, 1 being most consistent)
    /// </summary>
    public double TimePatternConsistency { get; set; } = 1.0;

    /// <summary>
    /// Percentage of requests that result in errors
    /// </summary>
    public double ErrorRate { get; set; } = 0.0;

    /// <summary>
    /// Most common User-Agent string
    /// </summary>
    [StringLength(500)]
    public string? PrimaryUserAgent { get; set; }

    /// <summary>
    /// Peak activity hours (0-23)
    /// </summary>
    public List<int> PeakActivityHours { get; set; } = new();

    /// <summary>
    /// Unique endpoints accessed
    /// </summary>
    public int UniqueEndpoints { get; set; } = 0;

    /// <summary>
    /// Behavioral anomaly score (0-100, higher means more anomalous)
    /// </summary>
    public double AnomalyScore { get; set; } = 0.0;

    /// <summary>
    /// When the behavioral profile was last updated
    /// </summary>
    public DateTime LastAnalyzed { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Categories for IP classification
/// </summary>
public enum IPCategory
{
    Unknown = 0,
    Residential = 1,
    Commercial = 2,
    Educational = 3,
    Government = 4,
    Hosting = 5,
    Bot = 6,
    Crawler = 7,
    Proxy = 8,
    VPN = 9,
    Tor = 10,
    CloudProvider = 11,
    CDN = 12,
    Malicious = 13,
    Spam = 14,
    Scanner = 15,
    Brute Force = 16
}