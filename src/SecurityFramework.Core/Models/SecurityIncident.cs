using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecurityFramework.Core.Models;

/// <summary>
/// Represents a security incident detected by the framework
/// </summary>
public class SecurityIncident
{
    /// <summary>
    /// Unique identifier for the incident
    /// </summary>
    [Key]
    public string IncidentId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Type of security incident
    /// </summary>
    [Required]
    public IncidentType Type { get; set; }

    /// <summary>
    /// Severity level of the incident
    /// </summary>
    [Required]
    public IncidentSeverity Severity { get; set; }

    /// <summary>
    /// Current status of the incident
    /// </summary>
    [Required]
    public IncidentStatus Status { get; set; } = IncidentStatus.Open;

    /// <summary>
    /// Brief title describing the incident
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of the incident
    /// </summary>
    [StringLength(2000)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Source IP address of the incident
    /// </summary>
    [StringLength(45)]
    [Index]
    public string? SourceIPAddress { get; set; }

    /// <summary>
    /// Target IP address (if applicable)
    /// </summary>
    [StringLength(45)]
    public string? TargetIPAddress { get; set; }

    /// <summary>
    /// User ID associated with the incident (if any)
    /// </summary>
    [StringLength(100)]
    [Index]
    public string? UserId { get; set; }

    /// <summary>
    /// Session ID when the incident occurred
    /// </summary>
    [StringLength(100)]
    public string? SessionId { get; set; }

    /// <summary>
    /// HTTP method of the request that triggered the incident
    /// </summary>
    [StringLength(10)]
    public string? HttpMethod { get; set; }

    /// <summary>
    /// URL path that was accessed
    /// </summary>
    [StringLength(2000)]
    public string? RequestPath { get; set; }

    /// <summary>
    /// User agent string
    /// </summary>
    [StringLength(1000)]
    public string? UserAgent { get; set; }

    /// <summary>
    /// Referer header
    /// </summary>
    [StringLength(2000)]
    public string? Referer { get; set; }

    /// <summary>
    /// Request payload (if relevant and safe to store)
    /// </summary>
    public string? RequestPayload { get; set; }

    /// <summary>
    /// Response status code
    /// </summary>
    public int? ResponseStatusCode { get; set; }

    /// <summary>
    /// Patterns that matched and triggered this incident
    /// </summary>
    public List<string> MatchedPatterns { get; set; } = new();

    /// <summary>
    /// Threat score that triggered the incident
    /// </summary>
    [Range(0, 100)]
    public double ThreatScore { get; set; }

    /// <summary>
    /// Confidence level in the detection (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// False positive likelihood (0-100)
    /// </summary>
    [Range(0, 100)]
    public double FalsePositiveLikelihood { get; set; } = 0.0;

    /// <summary>
    /// Action taken in response to the incident
    /// </summary>
    public IncidentResponse Response { get; set; } = IncidentResponse.None;

    /// <summary>
    /// Whether the incident was automatically handled
    /// </summary>
    public bool AutomaticallyHandled { get; set; } = false;

    /// <summary>
    /// Whether manual intervention is required
    /// </summary>
    public bool RequiresManualReview { get; set; } = false;

    /// <summary>
    /// Whether this incident has been escalated
    /// </summary>
    public bool Escalated { get; set; } = false;

    /// <summary>
    /// When the incident was escalated
    /// </summary>
    public DateTime? EscalatedAt { get; set; }

    /// <summary>
    /// Who the incident was escalated to
    /// </summary>
    [StringLength(200)]
    public string? EscalatedTo { get; set; }

    /// <summary>
    /// Related incidents (for correlation)
    /// </summary>
    public List<string> RelatedIncidentIds { get; set; } = new();

    /// <summary>
    /// Evidence collected for this incident
    /// </summary>
    public List<IncidentEvidence> Evidence { get; set; } = new();

    /// <summary>
    /// Timeline of actions taken
    /// </summary>
    public List<IncidentTimelineEntry> Timeline { get; set; } = new();

    /// <summary>
    /// Tags for categorization and searching
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// When the incident was first detected
    /// </summary>
    [Index]
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the incident was resolved (if resolved)
    /// </summary>
    public DateTime? ResolvedAt { get; set; }

    /// <summary>
    /// Who resolved the incident
    /// </summary>
    [StringLength(200)]
    public string? ResolvedBy { get; set; }

    /// <summary>
    /// Resolution notes
    /// </summary>
    [StringLength(1000)]
    public string? ResolutionNotes { get; set; }

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
    /// Adds a timeline entry to the incident
    /// </summary>
    public void AddTimelineEntry(string action, string? details = null, string? actor = null)
    {
        Timeline.Add(new IncidentTimelineEntry
        {
            Timestamp = DateTime.UtcNow,
            Action = action,
            Details = details,
            Actor = actor
        });
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Escalates the incident
    /// </summary>
    public void Escalate(string escalatedTo, string? reason = null)
    {
        Escalated = true;
        EscalatedAt = DateTime.UtcNow;
        EscalatedTo = escalatedTo;
        AddTimelineEntry("Escalated", reason, escalatedTo);
    }

    /// <summary>
    /// Resolves the incident
    /// </summary>
    public void Resolve(string resolvedBy, string? notes = null)
    {
        Status = IncidentStatus.Resolved;
        ResolvedAt = DateTime.UtcNow;
        ResolvedBy = resolvedBy;
        ResolutionNotes = notes;
        AddTimelineEntry("Resolved", notes, resolvedBy);
    }

    /// <summary>
    /// Closes the incident
    /// </summary>
    public void Close(string closedBy, string? notes = null)
    {
        Status = IncidentStatus.Closed;
        AddTimelineEntry("Closed", notes, closedBy);
    }

    /// <summary>
    /// Calculates the time to resolution
    /// </summary>
    public TimeSpan? GetTimeToResolution()
    {
        return ResolvedAt.HasValue ? ResolvedAt.Value - DetectedAt : null;
    }
}

/// <summary>
/// Types of security incidents
/// </summary>
public enum IncidentType
{
    Unknown = 0,
    BruteForceAttack = 1,
    SQLInjection = 2,
    XSSAttempt = 3,
    CSRFAttempt = 4,
    ParameterJacking = 5,
    PathTraversal = 6,
    CommandInjection = 7,
    AuthenticationBypass = 8,
    AuthorizationBypass = 9,
    DataExfiltration = 10,
    DenialOfService = 11,
    SuspiciousActivity = 12,
    MaliciousBot = 13,
    WebScraping = 14,
    RateLimitExceeded = 15,
    ThreatIntelMatch = 16,
    AnomalousPattern = 17,
    GeographicAnomaly = 18,
    TimeBasedAnomaly = 19,
    ComplianceViolation = 20
}

/// <summary>
/// Severity levels for incidents
/// </summary>
public enum IncidentSeverity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// Status of security incidents
/// </summary>
public enum IncidentStatus
{
    Open = 1,
    InProgress = 2,
    Resolved = 3,
    Closed = 4,
    FalsePositive = 5
}

/// <summary>
/// Response actions taken for incidents
/// </summary>
public enum IncidentResponse
{
    None = 0,
    Logged = 1,
    Warned = 2,
    Throttled = 3,
    Blocked = 4,
    Quarantined = 5,
    Escalated = 6
}

/// <summary>
/// Evidence collected for an incident
/// </summary>
public class IncidentEvidence
{
    /// <summary>
    /// Type of evidence
    /// </summary>
    [Required]
    [StringLength(100)]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Description of the evidence
    /// </summary>
    [StringLength(500)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Evidence data (could be JSON, base64, etc.)
    /// </summary>
    public string? Data { get; set; }

    /// <summary>
    /// Hash of the evidence for integrity
    /// </summary>
    [StringLength(128)]
    public string? Hash { get; set; }

    /// <summary>
    /// When the evidence was collected
    /// </summary>
    public DateTime CollectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Who or what collected the evidence
    /// </summary>
    [StringLength(200)]
    public string? CollectedBy { get; set; }
}

/// <summary>
/// Timeline entry for incident tracking
/// </summary>
public class IncidentTimelineEntry
{
    /// <summary>
    /// When the action occurred
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Action that was taken
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Additional details about the action
    /// </summary>
    [StringLength(1000)]
    public string? Details { get; set; }

    /// <summary>
    /// Who or what performed the action
    /// </summary>
    [StringLength(200)]
    public string? Actor { get; set; }
}