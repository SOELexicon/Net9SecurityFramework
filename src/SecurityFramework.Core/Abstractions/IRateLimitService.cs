namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Service for managing rate limiting and throttling
/// </summary>
public interface IRateLimitService
{
    /// <summary>
    /// Checks if a request is allowed based on rate limiting rules
    /// </summary>
    /// <param name="key">Rate limit key (e.g., IP address, user ID)</param>
    /// <param name="policy">Rate limiting policy to apply</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Rate limit result</returns>
    Task<RateLimitResult> CheckRateLimitAsync(string key, RateLimitPolicy policy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a request is allowed (synchronous version)
    /// </summary>
    /// <param name="key">Rate limit key</param>
    /// <param name="policy">Rate limiting policy to apply</param>
    /// <returns>Rate limit result</returns>
    RateLimitResult CheckRateLimit(string key, RateLimitPolicy policy);

    /// <summary>
    /// Records a request for rate limiting tracking
    /// </summary>
    /// <param name="key">Rate limit key</param>
    /// <param name="policy">Rate limiting policy</param>
    /// <param name="cost">Cost of the request (default: 1)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task RecordRequestAsync(string key, RateLimitPolicy policy, int cost = 1, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets current rate limit status for a key
    /// </summary>
    /// <param name="key">Rate limit key</param>
    /// <param name="policy">Rate limiting policy</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Current rate limit status</returns>
    Task<RateLimitStatus> GetStatusAsync(string key, RateLimitPolicy policy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resets rate limit for a specific key
    /// </summary>
    /// <param name="key">Rate limit key to reset</param>
    /// <param name="policy">Rate limiting policy</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task ResetRateLimitAsync(string key, RateLimitPolicy policy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets rate limiting statistics
    /// </summary>
    /// <param name="timeWindow">Time window for statistics</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Rate limiting statistics</returns>
    Task<RateLimitStatistics> GetStatisticsAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds or updates a rate limiting policy
    /// </summary>
    /// <param name="policy">Rate limiting policy to add or update</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task SetPolicyAsync(RateLimitPolicy policy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a rate limiting policy
    /// </summary>
    /// <param name="policyName">Name of the policy to remove</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task RemovePolicyAsync(string policyName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all configured rate limiting policies
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Collection of rate limiting policies</returns>
    Task<IEnumerable<RateLimitPolicy>> GetPoliciesAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a rate limit check
/// </summary>
public class RateLimitResult
{
    /// <summary>
    /// Whether the request is allowed
    /// </summary>
    public bool IsAllowed { get; set; }

    /// <summary>
    /// Reason for the rate limiting decision
    /// </summary>
    public string Reason { get; set; } = "";

    /// <summary>
    /// Current request count in the time window
    /// </summary>
    public long CurrentCount { get; set; }

    /// <summary>
    /// Maximum allowed requests in the time window
    /// </summary>
    public long Limit { get; set; }

    /// <summary>
    /// Remaining requests in the current time window
    /// </summary>
    public long Remaining => Math.Max(0, Limit - CurrentCount);

    /// <summary>
    /// Time when the rate limit window resets
    /// </summary>
    public DateTime ResetTime { get; set; }

    /// <summary>
    /// Time remaining until the window resets
    /// </summary>
    public TimeSpan TimeUntilReset => ResetTime > DateTime.UtcNow ? ResetTime - DateTime.UtcNow : TimeSpan.Zero;

    /// <summary>
    /// Retry after duration (for blocked requests)
    /// </summary>
    public TimeSpan? RetryAfter { get; set; }

    /// <summary>
    /// Policy that was applied
    /// </summary>
    public string PolicyName { get; set; } = "";

    /// <summary>
    /// Additional metadata about the rate limit decision
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Rate limiting policy configuration
/// </summary>
public class RateLimitPolicy
{
    /// <summary>
    /// Policy name/identifier
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Rate limiting algorithm to use
    /// </summary>
    public RateLimitAlgorithm Algorithm { get; set; } = RateLimitAlgorithm.FixedWindow;

    /// <summary>
    /// Maximum number of requests allowed in the time window
    /// </summary>
    public long Limit { get; set; } = 100;

    /// <summary>
    /// Time window for the rate limit
    /// </summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Whether this policy is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Priority of this policy (higher = more priority)
    /// </summary>
    public int Priority { get; set; } = 1;

    /// <summary>
    /// Conditions for applying this policy
    /// </summary>
    public List<RateLimitCondition> Conditions { get; set; } = new();

    /// <summary>
    /// Actions to take when rate limit is exceeded
    /// </summary>
    public List<RateLimitAction> Actions { get; set; } = new();

    /// <summary>
    /// Custom configuration for the algorithm
    /// </summary>
    public Dictionary<string, object> AlgorithmConfig { get; set; } = new();

    /// <summary>
    /// Whether to include this policy in statistics
    /// </summary>
    public bool IncludeInStatistics { get; set; } = true;

    /// <summary>
    /// Description of the policy
    /// </summary>
    public string Description { get; set; } = "";

    /// <summary>
    /// Tags for categorizing the policy
    /// </summary>
    public List<string> Tags { get; set; } = new();
}

/// <summary>
/// Current rate limit status for a key
/// </summary>
public class RateLimitStatus
{
    /// <summary>
    /// Rate limit key
    /// </summary>
    public string Key { get; set; } = "";

    /// <summary>
    /// Policy being applied
    /// </summary>
    public string PolicyName { get; set; } = "";

    /// <summary>
    /// Current request count
    /// </summary>
    public long CurrentCount { get; set; }

    /// <summary>
    /// Maximum allowed requests
    /// </summary>
    public long Limit { get; set; }

    /// <summary>
    /// Remaining requests
    /// </summary>
    public long Remaining => Math.Max(0, Limit - CurrentCount);

    /// <summary>
    /// Current window start time
    /// </summary>
    public DateTime WindowStart { get; set; }

    /// <summary>
    /// Current window end time
    /// </summary>
    public DateTime WindowEnd { get; set; }

    /// <summary>
    /// Whether the key is currently rate limited
    /// </summary>
    public bool IsRateLimited { get; set; }

    /// <summary>
    /// Time when the rate limit was first applied
    /// </summary>
    public DateTime? RateLimitedSince { get; set; }

    /// <summary>
    /// Last request timestamp
    /// </summary>
    public DateTime? LastRequest { get; set; }

    /// <summary>
    /// Total requests made by this key
    /// </summary>
    public long TotalRequests { get; set; }
}

/// <summary>
/// Rate limiting statistics
/// </summary>
public class RateLimitStatistics
{
    /// <summary>
    /// Time period for these statistics
    /// </summary>
    public TimeSpan TimePeriod { get; set; }

    /// <summary>
    /// Total requests processed
    /// </summary>
    public long TotalRequests { get; set; }

    /// <summary>
    /// Requests that were allowed
    /// </summary>
    public long AllowedRequests { get; set; }

    /// <summary>
    /// Requests that were blocked
    /// </summary>
    public long BlockedRequests { get; set; }

    /// <summary>
    /// Unique keys that were rate limited
    /// </summary>
    public long UniqueRateLimitedKeys { get; set; }

    /// <summary>
    /// Statistics by policy
    /// </summary>
    public Dictionary<string, PolicyStatistics> PolicyStatistics { get; set; } = new();

    /// <summary>
    /// Top rate limited keys
    /// </summary>
    public List<TopRateLimitedKey> TopRateLimitedKeys { get; set; } = new();

    /// <summary>
    /// Rate limiting effectiveness metrics
    /// </summary>
    public EffectivenessMetrics Effectiveness { get; set; } = new();

    /// <summary>
    /// Performance metrics
    /// </summary>
    public PerformanceMetrics Performance { get; set; } = new();
}

/// <summary>
/// Rate limiting algorithms
/// </summary>
public enum RateLimitAlgorithm
{
    /// <summary>
    /// Fixed window algorithm
    /// </summary>
    FixedWindow,

    /// <summary>
    /// Sliding window algorithm
    /// </summary>
    SlidingWindow,

    /// <summary>
    /// Token bucket algorithm
    /// </summary>
    TokenBucket,

    /// <summary>
    /// Leaky bucket algorithm
    /// </summary>
    LeakyBucket,

    /// <summary>
    /// Sliding window log algorithm
    /// </summary>
    SlidingWindowLog,

    /// <summary>
    /// Adaptive rate limiting
    /// </summary>
    Adaptive
}

/// <summary>
/// Condition for applying a rate limit policy
/// </summary>
public class RateLimitCondition
{
    /// <summary>
    /// Type of condition
    /// </summary>
    public ConditionType Type { get; set; }

    /// <summary>
    /// Property to check (e.g., "IP", "UserAgent", "Path")
    /// </summary>
    public string Property { get; set; } = "";

    /// <summary>
    /// Operator for the condition
    /// </summary>
    public ConditionOperator Operator { get; set; }

    /// <summary>
    /// Value to compare against
    /// </summary>
    public string Value { get; set; } = "";

    /// <summary>
    /// Whether the condition is case sensitive
    /// </summary>
    public bool CaseSensitive { get; set; } = false;

    /// <summary>
    /// Whether this condition should be negated
    /// </summary>
    public bool Negate { get; set; } = false;
}

/// <summary>
/// Action to take when rate limit is exceeded
/// </summary>
public class RateLimitAction
{
    /// <summary>
    /// Type of action
    /// </summary>
    public ActionType Type { get; set; }

    /// <summary>
    /// Configuration for the action
    /// </summary>
    public Dictionary<string, object> Configuration { get; set; } = new();
}

/// <summary>
/// Types of conditions
/// </summary>
public enum ConditionType
{
    IPAddress,
    UserAgent,
    RequestPath,
    Header,
    QueryParameter,
    ThreatScore,
    Time,
    Custom
}

/// <summary>
/// Condition operators
/// </summary>
public enum ConditionOperator
{
    Equals,
    NotEquals,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Matches, // Regex
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    In,
    NotIn
}

/// <summary>
/// Types of actions
/// </summary>
public enum ActionType
{
    Block,
    Throttle,
    Log,
    Alert,
    Redirect,
    Challenge,
    Custom
}

/// <summary>
/// Statistics for a specific policy
/// </summary>
public class PolicyStatistics
{
    /// <summary>
    /// Policy name
    /// </summary>
    public string PolicyName { get; set; } = "";

    /// <summary>
    /// Total requests processed by this policy
    /// </summary>
    public long TotalRequests { get; set; }

    /// <summary>
    /// Requests allowed by this policy
    /// </summary>
    public long AllowedRequests { get; set; }

    /// <summary>
    /// Requests blocked by this policy
    /// </summary>
    public long BlockedRequests { get; set; }

    /// <summary>
    /// Average processing time for this policy
    /// </summary>
    public double AverageProcessingTime { get; set; }

    /// <summary>
    /// Unique keys affected by this policy
    /// </summary>
    public long UniqueKeys { get; set; }
}

/// <summary>
/// Information about a heavily rate limited key
/// </summary>
public class TopRateLimitedKey
{
    /// <summary>
    /// Rate limit key
    /// </summary>
    public string Key { get; set; } = "";

    /// <summary>
    /// Total requests made by this key
    /// </summary>
    public long TotalRequests { get; set; }

    /// <summary>
    /// Requests blocked for this key
    /// </summary>
    public long BlockedRequests { get; set; }

    /// <summary>
    /// Policies that affected this key
    /// </summary>
    public List<string> AffectedPolicies { get; set; } = new();

    /// <summary>
    /// First seen timestamp
    /// </summary>
    public DateTime FirstSeen { get; set; }

    /// <summary>
    /// Last seen timestamp
    /// </summary>
    public DateTime LastSeen { get; set; }
}

/// <summary>
/// Rate limiting effectiveness metrics
/// </summary>
public class EffectivenessMetrics
{
    /// <summary>
    /// Percentage of requests that were blocked
    /// </summary>
    public double BlockRate { get; set; }

    /// <summary>
    /// Percentage of legitimate requests that were blocked (false positives)
    /// </summary>
    public double FalsePositiveRate { get; set; }

    /// <summary>
    /// Percentage of malicious requests that were allowed (false negatives)
    /// </summary>
    public double FalseNegativeRate { get; set; }

    /// <summary>
    /// Average response time for rate limiting decisions
    /// </summary>
    public double AverageDecisionTime { get; set; }
}

/// <summary>
/// Performance metrics for rate limiting
/// </summary>
public class PerformanceMetrics
{
    /// <summary>
    /// Average time to process a rate limit check
    /// </summary>
    public double AverageCheckTime { get; set; }

    /// <summary>
    /// 95th percentile check time
    /// </summary>
    public double P95CheckTime { get; set; }

    /// <summary>
    /// 99th percentile check time
    /// </summary>
    public double P99CheckTime { get; set; }

    /// <summary>
    /// Memory usage for rate limiting data
    /// </summary>
    public long MemoryUsage { get; set; }

    /// <summary>
    /// Cache hit rate
    /// </summary>
    public double CacheHitRate { get; set; }
}