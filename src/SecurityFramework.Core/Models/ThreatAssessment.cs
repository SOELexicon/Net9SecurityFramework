using System.ComponentModel.DataAnnotations;

namespace SecurityFramework.Core.Models;

/// <summary>
/// Result of a security threat assessment
/// </summary>
public class ThreatAssessment
{
    /// <summary>
    /// Unique identifier for this assessment
    /// </summary>
    public string AssessmentId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// IP address that was assessed
    /// </summary>
    [Required]
    [StringLength(45)]
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// Overall threat score (0-100)
    /// </summary>
    [Range(0, 100)]
    public double ThreatScore { get; set; } = 0.0;

    /// <summary>
    /// Trust score for the IP (0-100)
    /// </summary>
    [Range(0, 100)]
    public double TrustScore { get; set; } = 50.0;

    /// <summary>
    /// Combined risk score (0-100)
    /// </summary>
    [Range(0, 100)]
    public double RiskScore { get; set; } = 0.0;

    /// <summary>
    /// Threat level classification
    /// </summary>
    public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.Low;

    /// <summary>
    /// Recommended action based on the assessment
    /// </summary>
    public RecommendedAction RecommendedAction { get; set; } = RecommendedAction.Allow;

    /// <summary>
    /// Confidence in the assessment (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// Reason for the threat assessment result
    /// </summary>
    [StringLength(500)]
    public string? Reason { get; set; }

    /// <summary>
    /// Detailed explanation of the assessment
    /// </summary>
    [StringLength(2000)]
    public string? Details { get; set; }

    /// <summary>
    /// Flags that contributed to the assessment
    /// </summary>
    public List<string> Flags { get; set; } = new();

    /// <summary>
    /// Patterns that matched during assessment
    /// </summary>
    public List<PatternMatch> MatchedPatterns { get; set; } = new();

    /// <summary>
    /// Categories assigned to this IP
    /// </summary>
    public List<IPCategory> Categories { get; set; } = new();

    /// <summary>
    /// Geographic risk factors
    /// </summary>
    public GeographicRisk? GeographicRisk { get; set; }

    /// <summary>
    /// Behavioral analysis results
    /// </summary>
    public BehavioralRisk? BehavioralRisk { get; set; }

    /// <summary>
    /// Threat intelligence matches
    /// </summary>
    public List<ThreatIntelMatch> ThreatIntelMatches { get; set; } = new();

    /// <summary>
    /// Whether this assessment was enhanced with ML
    /// </summary>
    public bool MLEnhanced { get; set; } = false;

    /// <summary>
    /// ML confidence score (if ML enhanced)
    /// </summary>
    [Range(0, 100)]
    public double? MLConfidence { get; set; }

    /// <summary>
    /// Base score before ML enhancement
    /// </summary>
    [Range(0, 100)]
    public double? BaseScore { get; set; }

    /// <summary>
    /// ML-derived score
    /// </summary>
    [Range(0, 100)]
    public double? MLScore { get; set; }

    /// <summary>
    /// Assessment processing time in milliseconds
    /// </summary>
    public double ProcessingTimeMs { get; set; } = 0.0;

    /// <summary>
    /// When the assessment was performed
    /// </summary>
    public DateTime AssessedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// How long this assessment remains valid
    /// </summary>
    public TimeSpan ValidFor { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// When this assessment expires
    /// </summary>
    public DateTime ExpiresAt => AssessedAt.Add(ValidFor);

    /// <summary>
    /// Source of the assessment (rule-based, ML, hybrid, etc.)
    /// </summary>
    [StringLength(50)]
    public string Source { get; set; } = "RuleBased";

    /// <summary>
    /// Version of the assessment engine
    /// </summary>
    [StringLength(20)]
    public string EngineVersion { get; set; } = "1.0.0";

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// Checks if the assessment has expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;

    /// <summary>
    /// Determines if the request should be blocked based on threat level
    /// </summary>
    public bool ShouldBlock => ThreatLevel >= ThreatLevel.High || 
                              RecommendedAction == RecommendedAction.Block;

    /// <summary>
    /// Determines if the request should be challenged
    /// </summary>
    public bool ShouldChallenge => ThreatLevel == ThreatLevel.Medium || 
                                  RecommendedAction == RecommendedAction.Challenge;

    /// <summary>
    /// Gets a summary of the assessment for logging
    /// </summary>
    public string GetSummary()
    {
        return $"IP: {IPAddress}, Threat: {ThreatScore:F1}, Level: {ThreatLevel}, Action: {RecommendedAction}";
    }

    /// <summary>
    /// Gets the highest scoring pattern match
    /// </summary>
    public PatternMatch? GetHighestScoringPattern()
    {
        return MatchedPatterns.OrderByDescending(p => p.Score).FirstOrDefault();
    }

    /// <summary>
    /// Combines multiple threat assessments into a single result
    /// </summary>
    public static ThreatAssessment Combine(params ThreatAssessment[] assessments)
    {
        if (assessments == null || assessments.Length == 0)
            throw new ArgumentException("At least one assessment is required", nameof(assessments));

        if (assessments.Length == 1)
            return assessments[0];

        var combined = new ThreatAssessment
        {
            IPAddress = assessments[0].IPAddress,
            ThreatScore = assessments.Max(a => a.ThreatScore),
            TrustScore = assessments.Min(a => a.TrustScore),
            Confidence = assessments.Average(a => a.Confidence),
            ProcessingTimeMs = assessments.Sum(a => a.ProcessingTimeMs),
            Source = "Combined"
        };

        // Combine flags and patterns
        combined.Flags = assessments.SelectMany(a => a.Flags).Distinct().ToList();
        combined.MatchedPatterns = assessments.SelectMany(a => a.MatchedPatterns).ToList();
        combined.Categories = assessments.SelectMany(a => a.Categories).Distinct().ToList();
        combined.ThreatIntelMatches = assessments.SelectMany(a => a.ThreatIntelMatches).ToList();

        // Calculate risk score and determine action
        combined.RiskScore = (combined.ThreatScore + (100 - combined.TrustScore)) / 2;
        combined.ThreatLevel = DetermineThreatLevel(combined.ThreatScore);
        combined.RecommendedAction = DetermineRecommendedAction(combined.ThreatLevel, combined.ThreatScore);

        return combined;
    }

    private static ThreatLevel DetermineThreatLevel(double score)
    {
        return score switch
        {
            >= 80 => ThreatLevel.Critical,
            >= 60 => ThreatLevel.High,
            >= 40 => ThreatLevel.Medium,
            >= 20 => ThreatLevel.Low,
            _ => ThreatLevel.Minimal
        };
    }

    private static RecommendedAction DetermineRecommendedAction(ThreatLevel level, double score)
    {
        return level switch
        {
            ThreatLevel.Critical => RecommendedAction.Block,
            ThreatLevel.High => score >= 90 ? RecommendedAction.Block : RecommendedAction.Challenge,
            ThreatLevel.Medium => RecommendedAction.Challenge,
            ThreatLevel.Low => RecommendedAction.Monitor,
            _ => RecommendedAction.Allow
        };
    }
}

/// <summary>
/// Threat levels for classification
/// </summary>
public enum ThreatLevel
{
    Minimal = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// Recommended actions based on threat assessment
/// </summary>
public enum RecommendedAction
{
    Allow = 0,
    Monitor = 1,
    Challenge = 2,
    Throttle = 3,
    Block = 4,
    Quarantine = 5
}

/// <summary>
/// Result of a pattern match
/// </summary>
public class PatternMatch
{
    /// <summary>
    /// ID of the matched pattern
    /// </summary>
    [Required]
    public string PatternId { get; set; } = string.Empty;

    /// <summary>
    /// Name of the matched pattern
    /// </summary>
    [Required]
    [StringLength(200)]
    public string PatternName { get; set; } = string.Empty;

    /// <summary>
    /// Score assigned by this pattern (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Score { get; set; } = 0.0;

    /// <summary>
    /// Confidence in the match (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// Rules that matched within the pattern
    /// </summary>
    public List<string> MatchedRules { get; set; } = new();

    /// <summary>
    /// Specific values that triggered the match
    /// </summary>
    public Dictionary<string, string> TriggerValues { get; set; } = new();

    /// <summary>
    /// Additional context about the match
    /// </summary>
    public Dictionary<string, object> Context { get; set; } = new();

    /// <summary>
    /// When the match occurred
    /// </summary>
    public DateTime MatchedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Geographic risk assessment
/// </summary>
public class GeographicRisk
{
    /// <summary>
    /// Country risk score (0-100)
    /// </summary>
    [Range(0, 100)]
    public double CountryRisk { get; set; } = 0.0;

    /// <summary>
    /// Region risk score (0-100)
    /// </summary>
    [Range(0, 100)]
    public double RegionRisk { get; set; } = 0.0;

    /// <summary>
    /// ISP risk score (0-100)
    /// </summary>
    [Range(0, 100)]
    public double ISPRisk { get; set; } = 0.0;

    /// <summary>
    /// Whether the location is considered high-risk
    /// </summary>
    public bool IsHighRiskLocation { get; set; } = false;

    /// <summary>
    /// Whether the IP is from a known VPN/Proxy
    /// </summary>
    public bool IsVPNOrProxy { get; set; } = false;

    /// <summary>
    /// Whether the IP is from a Tor exit node
    /// </summary>
    public bool IsTorExitNode { get; set; } = false;

    /// <summary>
    /// Distance from usual geographic pattern (km)
    /// </summary>
    public double? DistanceFromNormal { get; set; }

    /// <summary>
    /// Risk factors that contributed to the score
    /// </summary>
    public List<string> RiskFactors { get; set; } = new();
}

/// <summary>
/// Behavioral risk assessment
/// </summary>
public class BehavioralRisk
{
    /// <summary>
    /// Anomaly score based on behavioral patterns (0-100)
    /// </summary>
    [Range(0, 100)]
    public double AnomalyScore { get; set; } = 0.0;

    /// <summary>
    /// Request frequency risk (0-100)
    /// </summary>
    [Range(0, 100)]
    public double FrequencyRisk { get; set; } = 0.0;

    /// <summary>
    /// Pattern deviation from normal behavior (0-100)
    /// </summary>
    [Range(0, 100)]
    public double PatternDeviation { get; set; } = 0.0;

    /// <summary>
    /// User agent consistency score (0-100, higher is more consistent)
    /// </summary>
    [Range(0, 100)]
    public double UserAgentConsistency { get; set; } = 100.0;

    /// <summary>
    /// Session behavior score (0-100)
    /// </summary>
    [Range(0, 100)]
    public double SessionBehavior { get; set; } = 0.0;

    /// <summary>
    /// Whether behavior indicates bot activity
    /// </summary>
    public bool IndicatesBotActivity { get; set; } = false;

    /// <summary>
    /// Whether behavior indicates scraping activity
    /// </summary>
    public bool IndicatesScrapingActivity { get; set; } = false;

    /// <summary>
    /// Behavioral anomalies detected
    /// </summary>
    public List<string> DetectedAnomalies { get; set; } = new();
}

/// <summary>
/// Threat intelligence match
/// </summary>
public class ThreatIntelMatch
{
    /// <summary>
    /// Source of the threat intelligence
    /// </summary>
    [Required]
    [StringLength(100)]
    public string Source { get; set; } = string.Empty;

    /// <summary>
    /// Type of threat intelligence
    /// </summary>
    [Required]
    [StringLength(50)]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Threat category
    /// </summary>
    [StringLength(100)]
    public string? Category { get; set; }

    /// <summary>
    /// Severity of the threat intel match
    /// </summary>
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;

    /// <summary>
    /// Confidence in the match (0-100)
    /// </summary>
    [Range(0, 100)]
    public double Confidence { get; set; } = 100.0;

    /// <summary>
    /// Description of the threat
    /// </summary>
    [StringLength(500)]
    public string? Description { get; set; }

    /// <summary>
    /// When the threat was first observed
    /// </summary>
    public DateTime? FirstSeen { get; set; }

    /// <summary>
    /// When the threat was last observed
    /// </summary>
    public DateTime? LastSeen { get; set; }

    /// <summary>
    /// Tags associated with the threat intel
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// Additional metadata from the threat intel source
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}