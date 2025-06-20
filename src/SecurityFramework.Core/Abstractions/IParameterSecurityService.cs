using SecurityFramework.Core.Models;

namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Service interface for parameter security and IDOR detection
/// </summary>
public interface IParameterSecurityService
{
    /// <summary>
    /// Validates request parameters for potential tampering or IDOR attempts
    /// </summary>
    /// <param name="request">Security request to validate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Parameter jacking detection result</returns>
    Task<ParameterJackingResult> ValidateRequestParametersAsync(SecurityRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates access to a specific resource
    /// </summary>
    /// <param name="userId">User attempting access</param>
    /// <param name="resourceType">Type of resource (e.g., "order", "user", "document")</param>
    /// <param name="resourceId">Identifier of the resource</param>
    /// <param name="operation">Operation being performed (read, write, delete, etc.)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if access is authorized, false otherwise</returns>
    Task<bool> ValidateResourceAccessAsync(string userId, string resourceType, string resourceId, string operation, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates access to a specific resource with detailed result
    /// </summary>
    /// <param name="accessRequest">Resource access request details</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Detailed resource access validation result</returns>
    Task<ResourceAccessResult> ValidateResourceAccessAsync(ResourceAccessRequest accessRequest, CancellationToken cancellationToken = default);

    /// <summary>
    /// Detects sequential parameter access patterns (enumeration attacks)
    /// </summary>
    /// <param name="userId">User making the requests</param>
    /// <param name="ipAddress">IP address of the requests</param>
    /// <param name="resourceType">Type of resource being accessed</param>
    /// <param name="timeWindow">Time window to analyze (default: 5 minutes)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Enumeration attack detection result</returns>
    Task<EnumerationDetectionResult> DetectEnumerationAttackAsync(string userId, string ipAddress, string resourceType, TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a parameter security incident
    /// </summary>
    /// <param name="incident">Parameter security incident to record</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Recorded incident with assigned ID</returns>
    Task<ParameterSecurityIncident> RecordIncidentAsync(ParameterSecurityIncident incident, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets parameter security incidents for a user
    /// </summary>
    /// <param name="userId">User ID to search for</param>
    /// <param name="fromDate">Start date for search</param>
    /// <param name="toDate">End date for search</param>
    /// <param name="incidentTypes">Types of incidents to include (null for all)</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of parameter security incidents</returns>
    Task<List<ParameterSecurityIncident>> GetIncidentsByUserAsync(string userId, DateTime? fromDate = null, DateTime? toDate = null, List<ParameterIncidentType>? incidentTypes = null, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets parameter security incidents for an IP address
    /// </summary>
    /// <param name="ipAddress">IP address to search for</param>
    /// <param name="fromDate">Start date for search</param>
    /// <param name="toDate">End date for search</param>
    /// <param name="incidentTypes">Types of incidents to include (null for all)</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of parameter security incidents</returns>
    Task<List<ParameterSecurityIncident>> GetIncidentsByIPAsync(string ipAddress, DateTime? fromDate = null, DateTime? toDate = null, List<ParameterIncidentType>? incidentTypes = null, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets parameter security incidents by type
    /// </summary>
    /// <param name="incidentType">Type of incident</param>
    /// <param name="fromDate">Start date for search</param>
    /// <param name="toDate">End date for search</param>
    /// <param name="limit">Maximum number of results</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of parameter security incidents</returns>
    Task<List<ParameterSecurityIncident>> GetIncidentsByTypeAsync(ParameterIncidentType incidentType, DateTime? fromDate = null, DateTime? toDate = null, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets parameter security statistics
    /// </summary>
    /// <param name="fromDate">Start date for statistics</param>
    /// <param name="toDate">End date for statistics</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Parameter security statistics</returns>
    Task<ParameterSecurityStatistics> GetStatisticsAsync(DateTime fromDate, DateTime toDate, CancellationToken cancellationToken = default);

    /// <summary>
    /// Configures parameter security rules for a resource type
    /// </summary>
    /// <param name="resourceType">Type of resource</param>
    /// <param name="rules">Security rules to apply</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task ConfigureResourceSecurityAsync(string resourceType, List<ParameterSecurityRule> rules, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets configured security rules for a resource type
    /// </summary>
    /// <param name="resourceType">Type of resource</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of security rules</returns>
    Task<List<ParameterSecurityRule>> GetResourceSecurityRulesAsync(string resourceType, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates parameter patterns for suspicious activity
    /// </summary>
    /// <param name="parameterName">Name of the parameter</param>
    /// <param name="parameterValue">Value of the parameter</param>
    /// <param name="expectedPattern">Expected pattern for the parameter</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Parameter validation result</returns>
    Task<ParameterValidationResult> ValidateParameterPatternAsync(string parameterName, string parameterValue, string? expectedPattern = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a user has been involved in multiple IDOR attempts
    /// </summary>
    /// <param name="userId">User ID to check</param>
    /// <param name="timeWindow">Time window to analyze</param>
    /// <param name="threshold">Threshold for number of attempts</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if user exceeds threshold, false otherwise</returns>
    Task<bool> IsUserSuspiciousAsync(string userId, TimeSpan timeWindow, int threshold = 5, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets user risk score based on parameter security incidents
    /// </summary>
    /// <param name="userId">User ID to assess</param>
    /// <param name="timeWindow">Time window for analysis</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User risk score (0-100)</returns>
    Task<double> GetUserRiskScoreAsync(string userId, TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Resource access request details
/// </summary>
public class ResourceAccessRequest
{
    /// <summary>
    /// User requesting access
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// User roles
    /// </summary>
    public List<string> UserRoles { get; set; } = new();

    /// <summary>
    /// Type of resource
    /// </summary>
    public string ResourceType { get; set; } = string.Empty;

    /// <summary>
    /// Resource identifier
    /// </summary>
    public string ResourceId { get; set; } = string.Empty;

    /// <summary>
    /// Operation being performed
    /// </summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>
    /// IP address of the request
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// Session ID
    /// </summary>
    public string? SessionId { get; set; }

    /// <summary>
    /// Request timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> Context { get; set; } = new();
}

/// <summary>
/// Resource access validation result
/// </summary>
public class ResourceAccessResult
{
    /// <summary>
    /// Whether access is allowed
    /// </summary>
    public bool IsAllowed { get; set; }

    /// <summary>
    /// Reason for denial (if not allowed)
    /// </summary>
    public string? DenialReason { get; set; }

    /// <summary>
    /// Risk score of the access attempt (0-100)
    /// </summary>
    public double RiskScore { get; set; }

    /// <summary>
    /// Confidence in the decision (0-100)
    /// </summary>
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// Whether this should be logged as a security incident
    /// </summary>
    public bool ShouldLogIncident { get; set; }

    /// <summary>
    /// Recommended action
    /// </summary>
    public RecommendedAction RecommendedAction { get; set; } = RecommendedAction.Allow;

    /// <summary>
    /// Security checks that were performed
    /// </summary>
    public List<string> PerformedChecks { get; set; } = new();

    /// <summary>
    /// Security checks that failed
    /// </summary>
    public List<string> FailedChecks { get; set; } = new();

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Enumeration attack detection result
/// </summary>
public class EnumerationDetectionResult
{
    /// <summary>
    /// Whether enumeration attack was detected
    /// </summary>
    public bool IsEnumerationDetected { get; set; }

    /// <summary>
    /// Number of sequential attempts detected
    /// </summary>
    public int SequentialAttempts { get; set; }

    /// <summary>
    /// Time span of the attempts
    /// </summary>
    public TimeSpan AttackDuration { get; set; }

    /// <summary>
    /// Resource IDs that were attempted
    /// </summary>
    public List<string> AttemptedResourceIds { get; set; } = new();

    /// <summary>
    /// Success rate of the attempts
    /// </summary>
    public double SuccessRate { get; set; }

    /// <summary>
    /// Risk score of the enumeration attempt (0-100)
    /// </summary>
    public double RiskScore { get; set; }

    /// <summary>
    /// Recommended action
    /// </summary>
    public RecommendedAction RecommendedAction { get; set; } = RecommendedAction.Allow;

    /// <summary>
    /// Pattern detected (sequential, random, etc.)
    /// </summary>
    public string? DetectedPattern { get; set; }

    /// <summary>
    /// Confidence in detection (0-100)
    /// </summary>
    public double Confidence { get; set; } = 100.0;
}

/// <summary>
/// Parameter security rule
/// </summary>
public class ParameterSecurityRule
{
    /// <summary>
    /// Rule identifier
    /// </summary>
    public string RuleId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Rule name
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Resource type this rule applies to
    /// </summary>
    public string ResourceType { get; set; } = string.Empty;

    /// <summary>
    /// Parameter name this rule applies to
    /// </summary>
    public string ParameterName { get; set; } = string.Empty;

    /// <summary>
    /// Type of validation to perform
    /// </summary>
    public ParameterValidationType ValidationType { get; set; }

    /// <summary>
    /// Expected pattern or format
    /// </summary>
    public string? ExpectedPattern { get; set; }

    /// <summary>
    /// Whether the user must own the resource
    /// </summary>
    public bool RequireOwnership { get; set; } = true;

    /// <summary>
    /// Roles that are exempt from this rule
    /// </summary>
    public List<string> ExemptRoles { get; set; } = new();

    /// <summary>
    /// Whether this rule is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Severity of violations of this rule
    /// </summary>
    public IncidentSeverity Severity { get; set; } = IncidentSeverity.Medium;

    /// <summary>
    /// Action to take when rule is violated
    /// </summary>
    public ParameterRuleAction Action { get; set; } = ParameterRuleAction.Block;
}

/// <summary>
/// Parameter validation types
/// </summary>
public enum ParameterValidationType
{
    Format = 1,
    Ownership = 2,
    Permission = 3,
    Range = 4,
    Enumeration = 5,
    Custom = 6
}

/// <summary>
/// Actions to take when parameter rules are violated
/// </summary>
public enum ParameterRuleAction
{
    Allow = 1,
    Log = 2,
    Challenge = 3,
    Block = 4,
    Custom = 5
}

/// <summary>
/// Parameter validation result
/// </summary>
public class ParameterValidationResult
{
    /// <summary>
    /// Whether the parameter is valid
    /// </summary>
    public bool IsValid { get; set; } = true;

    /// <summary>
    /// Risk score of the parameter (0-100)
    /// </summary>
    public double RiskScore { get; set; } = 0.0;

    /// <summary>
    /// Validation errors
    /// </summary>
    public List<string> Errors { get; set; } = new();

    /// <summary>
    /// Validation warnings
    /// </summary>
    public List<string> Warnings { get; set; } = new();

    /// <summary>
    /// Detected anomalies
    /// </summary>
    public List<string> Anomalies { get; set; } = new();

    /// <summary>
    /// Recommended action
    /// </summary>
    public RecommendedAction RecommendedAction { get; set; } = RecommendedAction.Allow;
}

/// <summary>
/// Parameter security statistics
/// </summary>
public class ParameterSecurityStatistics
{
    /// <summary>
    /// Total number of parameter validation requests
    /// </summary>
    public long TotalValidations { get; set; }

    /// <summary>
    /// Number of blocked requests
    /// </summary>
    public long BlockedRequests { get; set; }

    /// <summary>
    /// Number of IDOR attempts detected
    /// </summary>
    public long IDORAttempts { get; set; }

    /// <summary>
    /// Number of enumeration attacks detected
    /// </summary>
    public long EnumerationAttempts { get; set; }

    /// <summary>
    /// Number of parameter tampering incidents
    /// </summary>
    public long TamperingIncidents { get; set; }

    /// <summary>
    /// Top targeted resource types
    /// </summary>
    public Dictionary<string, long> TopTargetedResources { get; set; } = new();

    /// <summary>
    /// Top attacking users
    /// </summary>
    public Dictionary<string, long> TopAttackingUsers { get; set; } = new();

    /// <summary>
    /// Top attacking IP addresses
    /// </summary>
    public Dictionary<string, long> TopAttackingIPs { get; set; } = new();

    /// <summary>
    /// Average risk score
    /// </summary>
    public double AverageRiskScore { get; set; }

    /// <summary>
    /// Success rate of attacks (successful unauthorized access)
    /// </summary>
    public double AttackSuccessRate { get; set; }

    /// <summary>
    /// False positive rate
    /// </summary>
    public double FalsePositiveRate { get; set; }

    /// <summary>
    /// Time period for statistics
    /// </summary>
    public DateTime StartDate { get; set; }

    /// <summary>
    /// End time for statistics
    /// </summary>
    public DateTime EndDate { get; set; }

    /// <summary>
    /// When statistics were generated
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
}