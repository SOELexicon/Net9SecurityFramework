using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;

namespace SecurityFramework.Core.Models;

/// <summary>
/// Represents a threat detection pattern
/// </summary>
public class ThreatPattern
{
    /// <summary>
    /// Unique identifier for the pattern
    /// </summary>
    [Key]
    public string PatternId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Human-readable name for the pattern
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of what this pattern detects
    /// </summary>
    [StringLength(1000)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Category of the threat pattern
    /// </summary>
    [Required]
    public ThreatCategory Category { get; set; }

    /// <summary>
    /// Subcategory for more specific classification
    /// </summary>
    [StringLength(100)]
    public string? Subcategory { get; set; }

    /// <summary>
    /// Severity of threats detected by this pattern
    /// </summary>
    [Required]
    public ThreatSeverity Severity { get; set; }

    /// <summary>
    /// Base threat score assigned when this pattern matches (0-100)
    /// </summary>
    [Range(0, 100)]
    public double BaseThreatScore { get; set; } = 50.0;

    /// <summary>
    /// Confidence level in this pattern's accuracy (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 90.0;

    /// <summary>
    /// Whether this pattern is currently enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Whether this pattern is built-in or custom
    /// </summary>
    public bool IsBuiltIn { get; set; } = false;

    /// <summary>
    /// Pattern matching rules
    /// </summary>
    public List<PatternRule> Rules { get; set; } = new();

    /// <summary>
    /// Conditions that must be met for the pattern to match
    /// </summary>
    public List<PatternCondition> Conditions { get; set; } = new();

    /// <summary>
    /// Actions to take when this pattern matches
    /// </summary>
    public List<PatternAction> Actions { get; set; } = new();

    /// <summary>
    /// Tags for categorization and filtering
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// MITRE ATT&CK technique IDs (if applicable)
    /// </summary>
    public List<string> MitreAttackTechniques { get; set; } = new();

    /// <summary>
    /// CVE references (if applicable)
    /// </summary>
    public List<string> CVEReferences { get; set; } = new();

    /// <summary>
    /// Reference URLs for more information
    /// </summary>
    public List<string> References { get; set; } = new();

    /// <summary>
    /// Pattern author/creator
    /// </summary>
    [StringLength(200)]
    public string? Author { get; set; }

    /// <summary>
    /// Pattern version
    /// </summary>
    [StringLength(20)]
    public string Version { get; set; } = "1.0.0";

    /// <summary>
    /// When the pattern was last updated
    /// </summary>
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Performance metrics for this pattern
    /// </summary>
    public PatternMetrics? Metrics { get; set; }

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// Record creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Version for optimistic concurrency
    /// </summary>
    [Timestamp]
    public byte[] RowVersion { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Validates if all rules and conditions are properly configured
    /// </summary>
    public bool IsValid()
    {
        return Rules.Any() && Rules.All(r => r.IsValid());
    }

    /// <summary>
    /// Gets the effective threat score based on base score and multipliers
    /// </summary>
    public double GetEffectiveThreatScore(ThreatContext? context = null)
    {
        var score = BaseThreatScore;
        
        if (context != null)
        {
            // Apply context-based multipliers
            if (context.IsOffHours)
                score *= 1.2;
            
            if (context.IsFromSuspiciousLocation)
                score *= 1.3;
                
            if (context.HasSuspiciousUserAgent)
                score *= 1.1;
        }
        
        return Math.Min(score, 100.0);
    }
}

/// <summary>
/// Categories for threat patterns
/// </summary>
public enum ThreatCategory
{
    Unknown = 0,
    Injection = 1,
    Authentication = 2,
    Authorization = 3,
    DataValidation = 4,
    SessionManagement = 5,
    Cryptography = 6,
    ErrorHandling = 7,
    Logging = 8,
    Communication = 9,
    SystemIntegrity = 10,
    FileUpload = 11,
    BusinessLogic = 12,
    ClientSide = 13,
    APIAbuse = 14,
    BotDetection = 15,
    OWASP = 16,
    Custom = 17
}

/// <summary>
/// Severity levels for threat patterns
/// </summary>
public enum ThreatSeverity
{
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

/// <summary>
/// A single rule within a threat pattern
/// </summary>
public class PatternRule
{
    /// <summary>
    /// Unique identifier for the rule
    /// </summary>
    public string RuleId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Name of the rule
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Type of rule
    /// </summary>
    [Required]
    public PatternRuleType Type { get; set; }

    /// <summary>
    /// Target field or data to analyze
    /// </summary>
    [Required]
    [StringLength(100)]
    public string Target { get; set; } = string.Empty;

    /// <summary>
    /// Operator for comparison
    /// </summary>
    [Required]
    public PatternOperator Operator { get; set; }

    /// <summary>
    /// Value to compare against
    /// </summary>
    [Required]
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// Additional options for the rule
    /// </summary>
    public Dictionary<string, object> Options { get; set; } = new();

    /// <summary>
    /// Whether this rule is case sensitive (for string operations)
    /// </summary>
    public bool CaseSensitive { get; set; } = false;

    /// <summary>
    /// Weight of this rule in the overall pattern score (0-1)
    /// </summary>
    [Range(0, 1)]
    public double Weight { get; set; } = 1.0;

    /// <summary>
    /// Whether this rule is required for the pattern to match
    /// </summary>
    public bool Required { get; set; } = true;

    /// <summary>
    /// Validates the rule configuration
    /// </summary>
    public bool IsValid()
    {
        return !string.IsNullOrWhiteSpace(Name) &&
               !string.IsNullOrWhiteSpace(Target) &&
               !string.IsNullOrWhiteSpace(Value);
    }
}

/// <summary>
/// Types of pattern rules
/// </summary>
public enum PatternRuleType
{
    Regex = 1,
    String = 2,
    Numeric = 3,
    Boolean = 4,
    IPAddress = 5,
    URL = 6,
    Header = 7,
    Parameter = 8,
    Payload = 9,
    UserAgent = 10,
    Referer = 11,
    Custom = 12
}

/// <summary>
/// Operators for pattern rule comparison
/// </summary>
public enum PatternOperator
{
    Equals = 1,
    NotEquals = 2,
    Contains = 3,
    NotContains = 4,
    StartsWith = 5,
    EndsWith = 6,
    Matches = 7,
    NotMatches = 8,
    GreaterThan = 9,
    LessThan = 10,
    GreaterOrEqual = 11,
    LessOrEqual = 12,
    InList = 13,
    NotInList = 14,
    IsEmpty = 15,
    IsNotEmpty = 16,
    LengthEquals = 17,
    LengthGreaterThan = 18,
    LengthLessThan = 19
}

/// <summary>
/// Conditions for pattern matching
/// </summary>
public class PatternCondition
{
    /// <summary>
    /// Type of condition
    /// </summary>
    [Required]
    public ConditionType Type { get; set; }

    /// <summary>
    /// Field to evaluate
    /// </summary>
    [Required]
    [StringLength(100)]
    public string Field { get; set; } = string.Empty;

    /// <summary>
    /// Operator for the condition
    /// </summary>
    [Required]
    public PatternOperator Operator { get; set; }

    /// <summary>
    /// Expected value
    /// </summary>
    [Required]
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// Whether this condition must be true for the pattern to match
    /// </summary>
    public bool Required { get; set; } = true;
}

/// <summary>
/// Types of pattern conditions
/// </summary>
public enum ConditionType
{
    HttpMethod = 1,
    StatusCode = 2,
    ContentType = 3,
    RequestSize = 4,
    ResponseSize = 5,
    ProcessingTime = 6,
    TimeOfDay = 7,
    DayOfWeek = 8,
    UserAuthenticated = 9,
    UserRole = 10,
    IPCategory = 11,
    Geographic = 12,
    Custom = 13
}

/// <summary>
/// Actions to take when a pattern matches
/// </summary>
public class PatternAction
{
    /// <summary>
    /// Type of action
    /// </summary>
    [Required]
    public ActionType Type { get; set; }

    /// <summary>
    /// Parameters for the action
    /// </summary>
    public Dictionary<string, object> Parameters { get; set; } = new();

    /// <summary>
    /// Priority of this action (higher numbers execute first)
    /// </summary>
    public int Priority { get; set; } = 0;

    /// <summary>
    /// Whether this action should be executed asynchronously
    /// </summary>
    public bool Async { get; set; } = false;
}

/// <summary>
/// Types of actions that can be taken
/// </summary>
public enum ActionType
{
    Log = 1,
    Block = 2,
    Challenge = 3,
    Throttle = 4,
    Redirect = 5,
    ModifyResponse = 6,
    IncrementCounter = 7,
    TriggerAlert = 8,
    UpdateThreatScore = 9,
    AddToBlocklist = 10,
    CreateIncident = 11,
    ExecuteCustom = 12
}

/// <summary>
/// Performance metrics for a pattern
/// </summary>
public class PatternMetrics
{
    /// <summary>
    /// Total number of times this pattern has been evaluated
    /// </summary>
    public long EvaluationCount { get; set; } = 0;

    /// <summary>
    /// Number of times this pattern has matched
    /// </summary>
    public long MatchCount { get; set; } = 0;

    /// <summary>
    /// Number of confirmed true positives
    /// </summary>
    public long TruePositives { get; set; } = 0;

    /// <summary>
    /// Number of confirmed false positives
    /// </summary>
    public long FalsePositives { get; set; } = 0;

    /// <summary>
    /// Average execution time in milliseconds
    /// </summary>
    public double AverageExecutionTime { get; set; } = 0.0;

    /// <summary>
    /// Maximum execution time in milliseconds
    /// </summary>
    public double MaxExecutionTime { get; set; } = 0.0;

    /// <summary>
    /// When metrics were last updated
    /// </summary>
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Calculates the match rate as a percentage
    /// </summary>
    public double GetMatchRate()
    {
        return EvaluationCount > 0 ? (double)MatchCount / EvaluationCount * 100 : 0;
    }

    /// <summary>
    /// Calculates the false positive rate as a percentage
    /// </summary>
    public double GetFalsePositiveRate()
    {
        var totalVerified = TruePositives + FalsePositives;
        return totalVerified > 0 ? (double)FalsePositives / totalVerified * 100 : 0;
    }

    /// <summary>
    /// Calculates the precision (true positives / all positives)
    /// </summary>
    public double GetPrecision()
    {
        var totalPositives = TruePositives + FalsePositives;
        return totalPositives > 0 ? (double)TruePositives / totalPositives : 0;
    }
}

/// <summary>
/// Context information for threat pattern evaluation
/// </summary>
public class ThreatContext
{
    /// <summary>
    /// Whether the request is during off-hours
    /// </summary>
    public bool IsOffHours { get; set; }

    /// <summary>
    /// Whether the request is from a suspicious geographic location
    /// </summary>
    public bool IsFromSuspiciousLocation { get; set; }

    /// <summary>
    /// Whether the user agent appears suspicious
    /// </summary>
    public bool HasSuspiciousUserAgent { get; set; }

    /// <summary>
    /// Current threat level for the IP
    /// </summary>
    public double IPThreatLevel { get; set; }

    /// <summary>
    /// User authentication status
    /// </summary>
    public bool IsAuthenticated { get; set; }

    /// <summary>
    /// User roles (if authenticated)
    /// </summary>
    public List<string> UserRoles { get; set; } = new();

    /// <summary>
    /// Session age in minutes
    /// </summary>
    public double SessionAge { get; set; }

    /// <summary>
    /// Request frequency from this IP
    /// </summary>
    public double RequestFrequency { get; set; }

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}