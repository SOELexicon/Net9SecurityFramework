using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecurityFramework.Core.Models;

/// <summary>
/// Represents a parameter security incident (IDOR, parameter jacking, etc.)
/// </summary>
public class ParameterSecurityIncident
{
    /// <summary>
    /// Unique identifier for the incident
    /// </summary>
    [Key]
    public string IncidentId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Type of parameter security incident
    /// </summary>
    [Required]
    public ParameterIncidentType Type { get; set; }

    /// <summary>
    /// Severity of the incident
    /// </summary>
    [Required]
    public IncidentSeverity Severity { get; set; }

    /// <summary>
    /// Current status of the incident
    /// </summary>
    [Required]
    public IncidentStatus Status { get; set; } = IncidentStatus.Open;

    /// <summary>
    /// User ID who made the request (if authenticated)
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
    /// IP address of the requester
    /// </summary>
    [Required]
    [StringLength(45)]
    [Index]
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// HTTP method used
    /// </summary>
    [Required]
    [StringLength(10)]
    public string HttpMethod { get; set; } = string.Empty;

    /// <summary>
    /// URL path that was accessed
    /// </summary>
    [Required]
    [StringLength(2000)]
    public string RequestPath { get; set; } = string.Empty;

    /// <summary>
    /// Parameter that was tampered with
    /// </summary>
    [Required]
    [StringLength(200)]
    public string ParameterName { get; set; } = string.Empty;

    /// <summary>
    /// Original parameter value (if known)
    /// </summary>
    [StringLength(1000)]
    public string? OriginalValue { get; set; }

    /// <summary>
    /// Attempted parameter value
    /// </summary>
    [Required]
    [StringLength(1000)]
    public string AttemptedValue { get; set; } = string.Empty;

    /// <summary>
    /// Expected value or pattern
    /// </summary>
    [StringLength(1000)]
    public string? ExpectedValue { get; set; }

    /// <summary>
    /// Resource type being accessed (order, user, document, etc.)
    /// </summary>
    [StringLength(100)]
    public string? ResourceType { get; set; }

    /// <summary>
    /// Resource ID that was attempted to be accessed
    /// </summary>
    [StringLength(100)]
    public string? ResourceId { get; set; }

    /// <summary>
    /// Owner of the resource (if different from requesting user)
    /// </summary>
    [StringLength(100)]
    public string? ResourceOwner { get; set; }

    /// <summary>
    /// Whether the user has legitimate access to the resource
    /// </summary>
    public bool HasLegitimateAccess { get; set; } = false;

    /// <summary>
    /// Description of what was attempted
    /// </summary>
    [StringLength(1000)]
    public string Description { get; set; } = string.Empty;

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
    /// Additional request headers (as JSON)
    /// </summary>
    public Dictionary<string, string> RequestHeaders { get; set; } = new();

    /// <summary>
    /// Query parameters (as JSON)
    /// </summary>
    public Dictionary<string, string> QueryParameters { get; set; } = new();

    /// <summary>
    /// Form parameters (as JSON)
    /// </summary>
    public Dictionary<string, string> FormParameters { get; set; } = new();

    /// <summary>
    /// Request body (if relevant and safe to store)
    /// </summary>
    public string? RequestBody { get; set; }

    /// <summary>
    /// Response status code
    /// </summary>
    public int ResponseStatusCode { get; set; }

    /// <summary>
    /// Response body (if relevant)
    /// </summary>
    public string? ResponseBody { get; set; }

    /// <summary>
    /// Whether the attempt was successful
    /// </summary>
    public bool AttemptSuccessful { get; set; } = false;

    /// <summary>
    /// Whether the request was blocked
    /// </summary>
    public bool Blocked { get; set; } = false;

    /// <summary>
    /// Reason for blocking (if blocked)
    /// </summary>
    [StringLength(500)]
    public string? BlockReason { get; set; }

    /// <summary>
    /// Confidence level in the detection (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// Likelihood this is a false positive (0-100)
    /// </summary>
    [Range(0, 100)]
    public double FalsePositiveLikelihood { get; set; } = 0.0;

    /// <summary>
    /// Risk score of this incident (0-100)
    /// </summary>
    [Range(0, 100)]
    public double RiskScore { get; set; } = 50.0;

    /// <summary>
    /// Detection method used
    /// </summary>
    [StringLength(100)]
    public string? DetectionMethod { get; set; }

    /// <summary>
    /// Rules or patterns that triggered the detection
    /// </summary>
    public List<string> TriggeredRules { get; set; } = new();

    /// <summary>
    /// Related incidents (for correlation)
    /// </summary>
    public List<string> RelatedIncidentIds { get; set; } = new();

    /// <summary>
    /// Evidence collected for this incident
    /// </summary>
    public List<ParameterIncidentEvidence> Evidence { get; set; } = new();

    /// <summary>
    /// Impact assessment of the incident
    /// </summary>
    public ParameterIncidentImpact? Impact { get; set; }

    /// <summary>
    /// Remediation actions taken
    /// </summary>
    public List<string> RemediationActions { get; set; } = new();

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// When the incident was detected
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
    /// Resolves the incident with notes
    /// </summary>
    public void Resolve(string resolvedBy, string? notes = null)
    {
        Status = IncidentStatus.Resolved;
        ResolvedAt = DateTime.UtcNow;
        ResolvedBy = resolvedBy;
        ResolutionNotes = notes;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Marks the incident as a false positive
    /// </summary>
    public void MarkAsFalsePositive(string markedBy, string? reason = null)
    {
        Status = IncidentStatus.FalsePositive;
        ResolvedAt = DateTime.UtcNow;
        ResolvedBy = markedBy;
        ResolutionNotes = $"False positive: {reason}";
        FalsePositiveLikelihood = 100.0;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets a descriptive summary of the incident
    /// </summary>
    public string GetSummary()
    {
        return $"{Type} attempt by {UserId ?? "anonymous"} on {ResourceType} {ResourceId} from {IPAddress}";
    }

    /// <summary>
    /// Determines if this represents a successful unauthorized access
    /// </summary>
    public bool IsSuccessfulUnauthorizedAccess()
    {
        return AttemptSuccessful && !HasLegitimateAccess;
    }
}

/// <summary>
/// Types of parameter security incidents
/// </summary>
public enum ParameterIncidentType
{
    Unknown = 0,
    IDORAttempt = 1,
    ParameterTampering = 2,
    AuthorizationBypass = 3,
    PrivilegeEscalation = 4,
    DataExposure = 5,
    UnauthorizedAccess = 6,
    SessionHijacking = 7,
    CrossUserDataAccess = 8,
    AdminFunctionAccess = 9,
    BulkDataAttempt = 10,
    SequentialAccess = 11,
    EnumerationAttempt = 12
}

/// <summary>
/// Evidence for parameter security incidents
/// </summary>
public class ParameterIncidentEvidence
{
    /// <summary>
    /// Type of evidence
    /// </summary>
    [Required]
    [StringLength(100)]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Name or identifier of the evidence
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Evidence content
    /// </summary>
    public string? Content { get; set; }

    /// <summary>
    /// Hash of the evidence for integrity
    /// </summary>
    [StringLength(128)]
    public string? Hash { get; set; }

    /// <summary>
    /// Content type (if applicable)
    /// </summary>
    [StringLength(100)]
    public string? ContentType { get; set; }

    /// <summary>
    /// Size of the evidence in bytes
    /// </summary>
    public long? SizeBytes { get; set; }

    /// <summary>
    /// When the evidence was collected
    /// </summary>
    public DateTime CollectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Source of the evidence
    /// </summary>
    [StringLength(200)]
    public string? Source { get; set; }

    /// <summary>
    /// Additional metadata about the evidence
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Impact assessment for parameter security incidents
/// </summary>
public class ParameterIncidentImpact
{
    /// <summary>
    /// Overall impact level
    /// </summary>
    public ImpactLevel Level { get; set; } = ImpactLevel.Unknown;

    /// <summary>
    /// Affected data types
    /// </summary>
    public List<string> AffectedDataTypes { get; set; } = new();

    /// <summary>
    /// Number of records potentially affected
    /// </summary>
    public long? AffectedRecordCount { get; set; }

    /// <summary>
    /// Users potentially affected
    /// </summary>
    public List<string> AffectedUsers { get; set; } = new();

    /// <summary>
    /// Systems or services potentially affected
    /// </summary>
    public List<string> AffectedSystems { get; set; } = new();

    /// <summary>
    /// Potential business impact
    /// </summary>
    [StringLength(1000)]
    public string? BusinessImpact { get; set; }

    /// <summary>
    /// Potential compliance impact
    /// </summary>
    [StringLength(1000)]
    public string? ComplianceImpact { get; set; }

    /// <summary>
    /// Whether sensitive data was accessed
    /// </summary>
    public bool SensitiveDataAccessed { get; set; } = false;

    /// <summary>
    /// Whether PII was potentially exposed
    /// </summary>
    public bool PIIExposed { get; set; } = false;

    /// <summary>
    /// Whether financial data was involved
    /// </summary>
    public bool FinancialDataInvolved { get; set; } = false;

    /// <summary>
    /// Estimated financial impact
    /// </summary>
    public decimal? EstimatedFinancialImpact { get; set; }

    /// <summary>
    /// Recovery time estimate
    /// </summary>
    public TimeSpan? EstimatedRecoveryTime { get; set; }
}

/// <summary>
/// Impact levels for security incidents
/// </summary>
public enum ImpactLevel
{
    Unknown = 0,
    Minimal = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

/// <summary>
/// Parameter jacking detection result
/// </summary>
public class ParameterJackingResult
{
    /// <summary>
    /// Whether parameter jacking was detected
    /// </summary>
    public bool IsJackingDetected { get; set; } = false;

    /// <summary>
    /// Type of jacking detected
    /// </summary>
    public ParameterIncidentType JackingType { get; set; } = ParameterIncidentType.Unknown;

    /// <summary>
    /// Confidence in the detection (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 0.0;

    /// <summary>
    /// Risk score of the detected activity (0-100)
    /// </summary>
    [Range(0, 100)]
    public double RiskScore { get; set; } = 0.0;

    /// <summary>
    /// Parameters that were identified as tampered
    /// </summary>
    public List<string> TamperedParameters { get; set; } = new();

    /// <summary>
    /// Evidence supporting the detection
    /// </summary>
    public List<string> Evidence { get; set; } = new();

    /// <summary>
    /// Recommended action
    /// </summary>
    public RecommendedAction RecommendedAction { get; set; } = RecommendedAction.Allow;

    /// <summary>
    /// Detailed explanation of the detection
    /// </summary>
    [StringLength(1000)]
    public string? Explanation { get; set; }

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// When the detection was performed
    /// </summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Processing time for the detection
    /// </summary>
    public double ProcessingTimeMs { get; set; } = 0.0;
}