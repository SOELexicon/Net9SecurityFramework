using SecurityFramework.Core.Models;

namespace SecurityFramework.Core.Services;

/// <summary>
/// Context for threat scoring calculations
/// </summary>
public class ThreatScoringContext
{
    /// <summary>
    /// IP address being scored
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// Current IP record (if exists)
    /// </summary>
    public IPRecord? ExistingRecord { get; set; }

    /// <summary>
    /// Time of the request being evaluated
    /// </summary>
    public DateTime? RequestTime { get; set; }

    /// <summary>
    /// Days since IP was last seen
    /// </summary>
    public int LastSeenDaysAgo { get; set; } = 0;

    /// <summary>
    /// Behavioral profile information
    /// </summary>
    public IPBehaviorProfile? BehaviorProfile { get; set; }

    /// <summary>
    /// Geographic information
    /// </summary>
    public IPGeographicInfo? GeographicInfo { get; set; }

    /// <summary>
    /// Pattern matches from current request
    /// </summary>
    public List<PatternMatch>? PatternMatches { get; set; }

    /// <summary>
    /// Threat intelligence matches
    /// </summary>
    public List<ThreatIntelMatch>? ThreatIntelMatches { get; set; }

    /// <summary>
    /// Whether IP is known to be malicious
    /// </summary>
    public bool IsKnownMalicious { get; set; } = false;

    /// <summary>
    /// Number of blocklist matches
    /// </summary>
    public int BlocklistMatches { get; set; } = 0;

    /// <summary>
    /// Number of previous security incidents
    /// </summary>
    public int PreviousIncidents { get; set; } = 0;

    /// <summary>
    /// Failed authentication attempts
    /// </summary>
    public int FailedAuthAttempts { get; set; } = 0;

    /// <summary>
    /// Requests per minute from this IP
    /// </summary>
    public double RequestsPerMinute { get; set; } = 0.0;

    /// <summary>
    /// Requests per hour from this IP
    /// </summary>
    public double RequestsPerHour { get; set; } = 0.0;

    /// <summary>
    /// Whether request burst was detected
    /// </summary>
    public bool HasRequestBurst { get; set; } = false;

    /// <summary>
    /// Number of rate limit violations
    /// </summary>
    public int RateLimitViolations { get; set; } = 0;

    /// <summary>
    /// Time between requests
    /// </summary>
    public TimeSpan? RequestInterval { get; set; }

    /// <summary>
    /// Whether this is a high-value target
    /// </summary>
    public bool IsHighValueTarget { get; set; } = false;

    /// <summary>
    /// Whether request comes from internal network
    /// </summary>
    public bool IsInternalNetwork { get; set; } = false;

    /// <summary>
    /// Whether there's valid business justification
    /// </summary>
    public bool HasValidBusinessJustification { get; set; } = false;

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

/// <summary>
/// Context for trust scoring calculations
/// </summary>
public class TrustScoringContext
{
    /// <summary>
    /// IP address being scored
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// Current IP record (if exists)
    /// </summary>
    public IPRecord? ExistingRecord { get; set; }

    /// <summary>
    /// Days since first seen
    /// </summary>
    public int DaysSinceFirstSeen { get; set; } = 0;

    /// <summary>
    /// Total number of requests
    /// </summary>
    public long TotalRequests { get; set; } = 0;

    /// <summary>
    /// Number of blocked requests
    /// </summary>
    public long BlockedRequests { get; set; } = 0;

    /// <summary>
    /// Number of security incidents
    /// </summary>
    public long SecurityIncidents { get; set; } = 0;

    /// <summary>
    /// Successful login attempts
    /// </summary>
    public int SuccessfulLogins { get; set; } = 0;

    /// <summary>
    /// Failed login attempts
    /// </summary>
    public int FailedLogins { get; set; } = 0;

    /// <summary>
    /// Behavioral profile information
    /// </summary>
    public IPBehaviorProfile? BehaviorProfile { get; set; }

    /// <summary>
    /// Whether IP is known to be good
    /// </summary>
    public bool IsKnownGood { get; set; } = false;

    /// <summary>
    /// Whether IP is whitelisted
    /// </summary>
    public bool IsWhitelisted { get; set; } = false;

    /// <summary>
    /// Whether this is a verified business
    /// </summary>
    public bool IsVerifiedBusiness { get; set; } = false;

    /// <summary>
    /// Whether this is a long-term partner
    /// </summary>
    public bool IsLongTermPartner { get; set; } = false;

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

/// <summary>
/// Result of threat score calculation
/// </summary>
public class ThreatScoreResult
{
    /// <summary>
    /// IP address that was scored
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// When the score was calculated
    /// </summary>
    public DateTime CalculatedAt { get; set; }

    /// <summary>
    /// Base threat score
    /// </summary>
    public double BaseScore { get; set; }

    /// <summary>
    /// Behavioral threat score
    /// </summary>
    public double BehavioralScore { get; set; }

    /// <summary>
    /// Geographic threat score
    /// </summary>
    public double GeographicScore { get; set; }

    /// <summary>
    /// Temporal threat score
    /// </summary>
    public double TemporalScore { get; set; }

    /// <summary>
    /// Pattern-based threat score
    /// </summary>
    public double PatternScore { get; set; }

    /// <summary>
    /// Frequency-based threat score
    /// </summary>
    public double FrequencyScore { get; set; }

    /// <summary>
    /// Reputation-based threat score
    /// </summary>
    public double ReputationScore { get; set; }

    /// <summary>
    /// Combined score before adjustments
    /// </summary>
    public double CombinedScore { get; set; }

    /// <summary>
    /// Score after contextual adjustments
    /// </summary>
    public double AdjustedScore { get; set; }

    /// <summary>
    /// Final threat score (0-100)
    /// </summary>
    public double FinalThreatScore { get; set; }

    /// <summary>
    /// Confidence in the score (0-100)
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Processing time in milliseconds
    /// </summary>
    public double ProcessingTimeMs { get; set; }

    /// <summary>
    /// Whether an error occurred during calculation
    /// </summary>
    public bool HasError { get; set; } = false;

    /// <summary>
    /// Error message if calculation failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Individual score components for analysis
    /// </summary>
    public Dictionary<string, double> ScoreComponents => new()
    {
        ["Base"] = BaseScore,
        ["Behavioral"] = BehavioralScore,
        ["Geographic"] = GeographicScore,
        ["Temporal"] = TemporalScore,
        ["Pattern"] = PatternScore,
        ["Frequency"] = FrequencyScore,
        ["Reputation"] = ReputationScore
    };
}

/// <summary>
/// Result of trust score calculation
/// </summary>
public class TrustScoreResult
{
    /// <summary>
    /// IP address that was scored
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// When the score was calculated
    /// </summary>
    public DateTime CalculatedAt { get; set; }

    /// <summary>
    /// History-based trust score
    /// </summary>
    public double HistoryScore { get; set; }

    /// <summary>
    /// Consistency-based trust score
    /// </summary>
    public double ConsistencyScore { get; set; }

    /// <summary>
    /// Authentication-based trust score
    /// </summary>
    public double AuthenticationScore { get; set; }

    /// <summary>
    /// Reputation-based trust score
    /// </summary>
    public double ReputationScore { get; set; }

    /// <summary>
    /// Behavior-based trust score
    /// </summary>
    public double BehaviorScore { get; set; }

    /// <summary>
    /// Combined score before adjustments
    /// </summary>
    public double CombinedScore { get; set; }

    /// <summary>
    /// Score after contextual adjustments
    /// </summary>
    public double AdjustedScore { get; set; }

    /// <summary>
    /// Final trust score (0-100)
    /// </summary>
    public double FinalTrustScore { get; set; }

    /// <summary>
    /// Confidence in the score (0-100)
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Processing time in milliseconds
    /// </summary>
    public double ProcessingTimeMs { get; set; }

    /// <summary>
    /// Whether an error occurred during calculation
    /// </summary>
    public bool HasError { get; set; } = false;

    /// <summary>
    /// Error message if calculation failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Individual score components for analysis
    /// </summary>
    public Dictionary<string, double> ScoreComponents => new()
    {
        ["History"] = HistoryScore,
        ["Consistency"] = ConsistencyScore,
        ["Authentication"] = AuthenticationScore,
        ["Reputation"] = ReputationScore,
        ["Behavior"] = BehaviorScore
    };
}

/// <summary>
/// Options for threat scoring engine
/// </summary>
public class ThreatScoringOptions
{
    /// <summary>
    /// Default threat score for unknown IPs
    /// </summary>
    public double DefaultThreatScore { get; set; } = 25.0;

    /// <summary>
    /// Default trust score for unknown IPs
    /// </summary>
    public double DefaultTrustScore { get; set; } = 50.0;

    /// <summary>
    /// High request frequency threshold (per minute)
    /// </summary>
    public double HighFrequencyThreshold { get; set; } = 60.0;

    /// <summary>
    /// Maximum user agent variations before considering suspicious
    /// </summary>
    public int MaxUserAgentVariations { get; set; } = 5;

    /// <summary>
    /// Minimum geographic consistency score
    /// </summary>
    public double MinGeographicConsistency { get; set; } = 0.7;

    /// <summary>
    /// Minimum time pattern consistency score
    /// </summary>
    public double MinTimeConsistency { get; set; } = 0.6;

    /// <summary>
    /// Maximum acceptable error rate
    /// </summary>
    public double MaxErrorRate { get; set; } = 0.1;

    /// <summary>
    /// Maximum geographic distance from normal (km)
    /// </summary>
    public double MaxGeographicDistance { get; set; } = 1000.0;

    /// <summary>
    /// Maximum requests per minute before flagging
    /// </summary>
    public double MaxRequestsPerMinute { get; set; } = 100.0;

    /// <summary>
    /// Maximum requests per hour before flagging
    /// </summary>
    public double MaxRequestsPerHour { get; set; } = 1000.0;

    /// <summary>
    /// Business start hour (24-hour format)
    /// </summary>
    public int BusinessStartHour { get; set; } = 9;

    /// <summary>
    /// Business end hour (24-hour format)
    /// </summary>
    public int BusinessEndHour { get; set; } = 17;

    /// <summary>
    /// Threat score weights
    /// </summary>
    public ThreatScoreWeights ThreatScoreWeights { get; set; } = new();

    /// <summary>
    /// Trust score weights
    /// </summary>
    public TrustScoreWeights TrustScoreWeights { get; set; } = new();
}

/// <summary>
/// Weights for combining threat scores
/// </summary>
public class ThreatScoreWeights
{
    /// <summary>
    /// Weight for base threat indicators
    /// </summary>
    public double BaseWeight { get; set; } = 0.25;

    /// <summary>
    /// Weight for behavioral analysis
    /// </summary>
    public double BehavioralWeight { get; set; } = 0.20;

    /// <summary>
    /// Weight for geographic analysis
    /// </summary>
    public double GeographicWeight { get; set; } = 0.15;

    /// <summary>
    /// Weight for temporal analysis
    /// </summary>
    public double TemporalWeight { get; set; } = 0.10;

    /// <summary>
    /// Weight for pattern matching
    /// </summary>
    public double PatternWeight { get; set; } = 0.15;

    /// <summary>
    /// Weight for frequency analysis
    /// </summary>
    public double FrequencyWeight { get; set; } = 0.10;

    /// <summary>
    /// Weight for reputation analysis
    /// </summary>
    public double ReputationWeight { get; set; } = 0.05;

    /// <summary>
    /// Total weight for normalization
    /// </summary>
    public double TotalWeight => BaseWeight + BehavioralWeight + GeographicWeight + 
                                TemporalWeight + PatternWeight + FrequencyWeight + ReputationWeight;
}

/// <summary>
/// Weights for combining trust scores
/// </summary>
public class TrustScoreWeights
{
    /// <summary>
    /// Weight for historical behavior
    /// </summary>
    public double HistoryWeight { get; set; } = 0.30;

    /// <summary>
    /// Weight for consistency metrics
    /// </summary>
    public double ConsistencyWeight { get; set; } = 0.25;

    /// <summary>
    /// Weight for authentication success
    /// </summary>
    public double AuthenticationWeight { get; set; } = 0.20;

    /// <summary>
    /// Weight for reputation
    /// </summary>
    public double ReputationWeight { get; set; } = 0.15;

    /// <summary>
    /// Weight for behavioral trust indicators
    /// </summary>
    public double BehaviorWeight { get; set; } = 0.10;

    /// <summary>
    /// Total weight for normalization
    /// </summary>
    public double TotalWeight => HistoryWeight + ConsistencyWeight + AuthenticationWeight + 
                                ReputationWeight + BehaviorWeight;
}

/// <summary>
/// Risk assessment result combining threat and trust scores
/// </summary>
public class RiskAssessmentResult
{
    /// <summary>
    /// IP address assessed
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// Threat score result
    /// </summary>
    public ThreatScoreResult ThreatScore { get; set; } = new();

    /// <summary>
    /// Trust score result
    /// </summary>
    public TrustScoreResult TrustScore { get; set; } = new();

    /// <summary>
    /// Combined risk score (0-100)
    /// </summary>
    public double RiskScore { get; set; }

    /// <summary>
    /// Overall confidence in assessment
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Recommended threat level
    /// </summary>
    public ThreatLevel ThreatLevel { get; set; }

    /// <summary>
    /// Recommended action
    /// </summary>
    public RecommendedAction RecommendedAction { get; set; }

    /// <summary>
    /// Explanation of the risk assessment
    /// </summary>
    public string Explanation { get; set; } = string.Empty;

    /// <summary>
    /// Risk factors identified
    /// </summary>
    public List<string> RiskFactors { get; set; } = new();

    /// <summary>
    /// Trust factors identified
    /// </summary>
    public List<string> TrustFactors { get; set; } = new();

    /// <summary>
    /// When the assessment was performed
    /// </summary>
    public DateTime AssessedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Total processing time
    /// </summary>
    public double TotalProcessingTimeMs { get; set; }
}