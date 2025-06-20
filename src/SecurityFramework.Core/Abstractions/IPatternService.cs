using SecurityFramework.Core.Models;

namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Service interface for managing and evaluating threat detection patterns
/// </summary>
public interface IPatternService
{
    /// <summary>
    /// Loads patterns from a directory
    /// </summary>
    /// <param name="patternDirectory">Directory containing pattern files</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Number of patterns loaded</returns>
    Task<int> LoadPatternsFromDirectoryAsync(string patternDirectory, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads a pattern from a JSON file
    /// </summary>
    /// <param name="filePath">Path to the pattern file</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Loaded threat pattern</returns>
    Task<ThreatPattern> LoadPatternFromFileAsync(string filePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Saves a pattern to a JSON file
    /// </summary>
    /// <param name="pattern">Pattern to save</param>
    /// <param name="filePath">Path where to save the pattern</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SavePatternToFileAsync(ThreatPattern pattern, string filePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates all enabled patterns against a request
    /// </summary>
    /// <param name="request">Request information to evaluate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of pattern matches</returns>
    Task<List<PatternMatch>> EvaluatePatternsAsync(SecurityRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates a specific pattern against a request
    /// </summary>
    /// <param name="pattern">Pattern to evaluate</param>
    /// <param name="request">Request information to evaluate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pattern match result, null if no match</returns>
    Task<PatternMatch?> EvaluatePatternAsync(ThreatPattern pattern, SecurityRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all available patterns
    /// </summary>
    /// <param name="includeDisabled">Whether to include disabled patterns</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of threat patterns</returns>
    Task<List<ThreatPattern>> GetPatternsAsync(bool includeDisabled = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets patterns by category
    /// </summary>
    /// <param name="category">Pattern category</param>
    /// <param name="includeDisabled">Whether to include disabled patterns</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of threat patterns in the category</returns>
    Task<List<ThreatPattern>> GetPatternsByCategoryAsync(ThreatCategory category, bool includeDisabled = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets patterns by severity
    /// </summary>
    /// <param name="severity">Pattern severity</param>
    /// <param name="includeDisabled">Whether to include disabled patterns</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of threat patterns with the specified severity</returns>
    Task<List<ThreatPattern>> GetPatternsBySeverityAsync(ThreatSeverity severity, bool includeDisabled = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a specific pattern by ID
    /// </summary>
    /// <param name="patternId">Pattern identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Threat pattern if found, null otherwise</returns>
    Task<ThreatPattern?> GetPatternAsync(string patternId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates or updates a pattern
    /// </summary>
    /// <param name="pattern">Pattern to save</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Saved threat pattern</returns>
    Task<ThreatPattern> SavePatternAsync(ThreatPattern pattern, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a pattern
    /// </summary>
    /// <param name="patternId">Pattern identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if deleted, false if not found</returns>
    Task<bool> DeletePatternAsync(string patternId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enables a pattern
    /// </summary>
    /// <param name="patternId">Pattern identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated pattern if found, null otherwise</returns>
    Task<ThreatPattern?> EnablePatternAsync(string patternId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables a pattern
    /// </summary>
    /// <param name="patternId">Pattern identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated pattern if found, null otherwise</returns>
    Task<ThreatPattern?> DisablePatternAsync(string patternId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates pattern performance metrics
    /// </summary>
    /// <param name="patternId">Pattern identifier</param>
    /// <param name="executionTime">Execution time in milliseconds</param>
    /// <param name="matched">Whether the pattern matched</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task UpdatePatternMetricsAsync(string patternId, double executionTime, bool matched, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records pattern feedback (true positive, false positive)
    /// </summary>
    /// <param name="patternId">Pattern identifier</param>
    /// <param name="isTruePositive">Whether this was a true positive</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RecordPatternFeedbackAsync(string patternId, bool isTruePositive, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets pattern performance statistics
    /// </summary>
    /// <param name="patternId">Pattern identifier (null for all patterns)</param>
    /// <param name="fromDate">Start date for statistics</param>
    /// <param name="toDate">End date for statistics</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pattern performance statistics</returns>
    Task<PatternStatistics> GetPatternStatisticsAsync(string? patternId = null, DateTime? fromDate = null, DateTime? toDate = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a pattern configuration
    /// </summary>
    /// <param name="pattern">Pattern to validate</param>
    /// <returns>Validation result</returns>
    Task<PatternValidationResult> ValidatePatternAsync(ThreatPattern pattern);

    /// <summary>
    /// Reloads all patterns from storage
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Number of patterns reloaded</returns>
    Task<int> ReloadPatternsAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Request information for pattern evaluation
/// </summary>
public class SecurityRequest
{
    /// <summary>
    /// IP address of the request
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// HTTP method
    /// </summary>
    public string HttpMethod { get; set; } = string.Empty;

    /// <summary>
    /// Request path
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Query string
    /// </summary>
    public string QueryString { get; set; } = string.Empty;

    /// <summary>
    /// Request headers
    /// </summary>
    public Dictionary<string, string[]> Headers { get; set; } = new();

    /// <summary>
    /// Form parameters
    /// </summary>
    public Dictionary<string, string[]> FormParameters { get; set; } = new();

    /// <summary>
    /// Query parameters
    /// </summary>
    public Dictionary<string, string[]> QueryParameters { get; set; } = new();

    /// <summary>
    /// Request body content
    /// </summary>
    public string? Body { get; set; }

    /// <summary>
    /// Content type
    /// </summary>
    public string? ContentType { get; set; }

    /// <summary>
    /// Content length
    /// </summary>
    public long? ContentLength { get; set; }

    /// <summary>
    /// User agent string
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Referer header
    /// </summary>
    public string? Referer { get; set; }

    /// <summary>
    /// User ID (if authenticated)
    /// </summary>
    public string? UserId { get; set; }

    /// <summary>
    /// Session ID
    /// </summary>
    public string? SessionId { get; set; }

    /// <summary>
    /// Is user authenticated
    /// </summary>
    public bool IsAuthenticated { get; set; }

    /// <summary>
    /// User roles
    /// </summary>
    public List<string> UserRoles { get; set; } = new();

    /// <summary>
    /// Request timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> AdditionalData { get; set; } = new();

    /// <summary>
    /// Gets header value by name
    /// </summary>
    /// <param name="headerName">Header name</param>
    /// <returns>Header value or null if not found</returns>
    public string? GetHeader(string headerName)
    {
        return Headers.TryGetValue(headerName, out var values) && values.Length > 0 
            ? values[0] 
            : null;
    }

    /// <summary>
    /// Gets query parameter value by name
    /// </summary>
    /// <param name="parameterName">Parameter name</param>
    /// <returns>Parameter value or null if not found</returns>
    public string? GetQueryParameter(string parameterName)
    {
        return QueryParameters.TryGetValue(parameterName, out var values) && values.Length > 0 
            ? values[0] 
            : null;
    }

    /// <summary>
    /// Gets form parameter value by name
    /// </summary>
    /// <param name="parameterName">Parameter name</param>
    /// <returns>Parameter value or null if not found</returns>
    public string? GetFormParameter(string parameterName)
    {
        return FormParameters.TryGetValue(parameterName, out var values) && values.Length > 0 
            ? values[0] 
            : null;
    }
}

/// <summary>
/// Pattern performance statistics
/// </summary>
public class PatternStatistics
{
    /// <summary>
    /// Total number of evaluations
    /// </summary>
    public long TotalEvaluations { get; set; }

    /// <summary>
    /// Total number of matches
    /// </summary>
    public long TotalMatches { get; set; }

    /// <summary>
    /// Match rate as percentage
    /// </summary>
    public double MatchRate => TotalEvaluations > 0 ? (double)TotalMatches / TotalEvaluations * 100 : 0;

    /// <summary>
    /// Average execution time in milliseconds
    /// </summary>
    public double AverageExecutionTime { get; set; }

    /// <summary>
    /// Maximum execution time in milliseconds
    /// </summary>
    public double MaxExecutionTime { get; set; }

    /// <summary>
    /// True positive count
    /// </summary>
    public long TruePositives { get; set; }

    /// <summary>
    /// False positive count
    /// </summary>
    public long FalsePositives { get; set; }

    /// <summary>
    /// False positive rate as percentage
    /// </summary>
    public double FalsePositiveRate
    {
        get
        {
            var totalVerified = TruePositives + FalsePositives;
            return totalVerified > 0 ? (double)FalsePositives / totalVerified * 100 : 0;
        }
    }

    /// <summary>
    /// Precision (true positives / all positives)
    /// </summary>
    public double Precision
    {
        get
        {
            var totalPositives = TruePositives + FalsePositives;
            return totalPositives > 0 ? (double)TruePositives / totalPositives : 0;
        }
    }

    /// <summary>
    /// Statistics by pattern
    /// </summary>
    public Dictionary<string, PatternMetrics> PatternMetrics { get; set; } = new();

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

/// <summary>
/// Pattern validation result
/// </summary>
public class PatternValidationResult
{
    /// <summary>
    /// Whether the pattern is valid
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Validation error messages
    /// </summary>
    public List<string> Errors { get; set; } = new();

    /// <summary>
    /// Validation warning messages
    /// </summary>
    public List<string> Warnings { get; set; } = new();

    /// <summary>
    /// Estimated performance impact
    /// </summary>
    public PerformanceImpact PerformanceImpact { get; set; } = PerformanceImpact.Low;

    /// <summary>
    /// Adds an error message
    /// </summary>
    /// <param name="message">Error message</param>
    public void AddError(string message)
    {
        Errors.Add(message);
        IsValid = false;
    }

    /// <summary>
    /// Adds a warning message
    /// </summary>
    /// <param name="message">Warning message</param>
    public void AddWarning(string message)
    {
        Warnings.Add(message);
    }
}

/// <summary>
/// Performance impact levels
/// </summary>
public enum PerformanceImpact
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}