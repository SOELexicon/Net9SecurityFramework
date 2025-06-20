using SecurityFramework.Core.Models;
using Microsoft.Extensions.Logging;

namespace SecurityFramework.Core.Services;

/// <summary>
/// Risk assessment engine that combines threat and trust scoring
/// </summary>
public class RiskAssessmentEngine : IRiskAssessmentEngine
{
    private readonly IThreatScoringEngine _threatScoringEngine;
    private readonly ILogger<RiskAssessmentEngine> _logger;
    private readonly RiskAssessmentOptions _options;

    public RiskAssessmentEngine(
        IThreatScoringEngine threatScoringEngine,
        ILogger<RiskAssessmentEngine> logger,
        RiskAssessmentOptions options)
    {
        _threatScoringEngine = threatScoringEngine ?? throw new ArgumentNullException(nameof(threatScoringEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Performs comprehensive risk assessment
    /// </summary>
    public async Task<RiskAssessmentResult> AssessRiskAsync(
        ThreatScoringContext threatContext, 
        TrustScoringContext trustContext)
    {
        var startTime = DateTime.UtcNow;
        
        try
        {
            var result = new RiskAssessmentResult
            {
                IPAddress = threatContext.IPAddress,
                AssessedAt = startTime
            };

            // Calculate threat score
            result.ThreatScore = await _threatScoringEngine.CalculateThreatScoreAsync(threatContext);

            // Calculate trust score
            result.TrustScore = await _threatScoringEngine.CalculateTrustScoreAsync(trustContext);

            // Combine into risk score
            result.RiskScore = CalculateRiskScore(result.ThreatScore, result.TrustScore);

            // Calculate overall confidence
            result.Confidence = CalculateOverallConfidence(result.ThreatScore, result.TrustScore);

            // Determine threat level
            result.ThreatLevel = DetermineThreatLevel(result.RiskScore);

            // Determine recommended action
            result.RecommendedAction = DetermineRecommendedAction(result.ThreatLevel, result.RiskScore);

            // Generate explanation
            result.Explanation = GenerateExplanation(result);

            // Identify risk and trust factors
            result.RiskFactors = IdentifyRiskFactors(result.ThreatScore, threatContext);
            result.TrustFactors = IdentifyTrustFactors(result.TrustScore, trustContext);

            // Calculate total processing time
            result.TotalProcessingTimeMs = result.ThreatScore.ProcessingTimeMs + 
                                         result.TrustScore.ProcessingTimeMs + 
                                         (DateTime.UtcNow - startTime).TotalMilliseconds;

            _logger.LogDebug("Risk assessment completed for {IPAddress}: Risk={Risk}, Threat={Threat}, Trust={Trust}", 
                result.IPAddress, result.RiskScore, result.ThreatScore.FinalThreatScore, result.TrustScore.FinalTrustScore);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error performing risk assessment for {IPAddress}", threatContext.IPAddress);
            
            return new RiskAssessmentResult
            {
                IPAddress = threatContext.IPAddress,
                RiskScore = 50.0, // Neutral risk on error
                Confidence = 25.0,
                ThreatLevel = ThreatLevel.Medium,
                RecommendedAction = RecommendedAction.Monitor,
                Explanation = $"Risk assessment failed: {ex.Message}",
                TotalProcessingTimeMs = (DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
    }

    /// <summary>
    /// Performs risk assessment for a single context (derives trust from threat data)
    /// </summary>
    public async Task<RiskAssessmentResult> AssessRiskAsync(ThreatScoringContext context)
    {
        // Derive trust context from threat context
        var trustContext = DeriveTrustContext(context);
        
        return await AssessRiskAsync(context, trustContext);
    }

    /// <summary>
    /// Calculates combined risk score from threat and trust scores
    /// </summary>
    private double CalculateRiskScore(ThreatScoreResult threatResult, TrustScoreResult trustResult)
    {
        if (threatResult.HasError && trustResult.HasError)
            return 50.0; // Neutral on double error

        var threatScore = threatResult.HasError ? 50.0 : threatResult.FinalThreatScore;
        var trustScore = trustResult.HasError ? 50.0 : trustResult.FinalTrustScore;

        // Risk score formula: weighted combination where low trust increases risk
        // Risk = (ThreatScore * ThreatWeight) + ((100 - TrustScore) * TrustWeight)
        var riskScore = (threatScore * _options.ThreatWeight) + 
                       ((100.0 - trustScore) * _options.TrustWeight);

        // Normalize by total weight
        riskScore /= (_options.ThreatWeight + _options.TrustWeight);

        // Apply risk amplification for high threat + low trust combinations
        if (threatScore > 70 && trustScore < 30)
        {
            riskScore *= _options.HighRiskAmplifier;
        }

        // Apply risk mitigation for low threat + high trust combinations
        if (threatScore < 30 && trustScore > 70)
        {
            riskScore *= _options.LowRiskMitigator;
        }

        return Math.Max(0, Math.Min(100, riskScore));
    }

    /// <summary>
    /// Calculates overall confidence from individual confidences
    /// </summary>
    private double CalculateOverallConfidence(ThreatScoreResult threatResult, TrustScoreResult trustResult)
    {
        var threatConfidence = threatResult.HasError ? 25.0 : threatResult.Confidence;
        var trustConfidence = trustResult.HasError ? 25.0 : trustResult.Confidence;

        // Overall confidence is the weighted average
        var overallConfidence = (threatConfidence * _options.ThreatWeight + 
                               trustConfidence * _options.TrustWeight) / 
                               (_options.ThreatWeight + _options.TrustWeight);

        // Reduce confidence if either component had errors
        if (threatResult.HasError || trustResult.HasError)
        {
            overallConfidence *= 0.7;
        }

        return Math.Max(0, Math.Min(100, overallConfidence));
    }

    /// <summary>
    /// Determines threat level based on risk score
    /// </summary>
    private ThreatLevel DetermineThreatLevel(double riskScore)
    {
        return riskScore switch
        {
            >= _options.CriticalThreshold => ThreatLevel.Critical,
            >= _options.HighThreshold => ThreatLevel.High,
            >= _options.MediumThreshold => ThreatLevel.Medium,
            >= _options.LowThreshold => ThreatLevel.Low,
            _ => ThreatLevel.Minimal
        };
    }

    /// <summary>
    /// Determines recommended action based on threat level and risk score
    /// </summary>
    private RecommendedAction DetermineRecommendedAction(ThreatLevel threatLevel, double riskScore)
    {
        return threatLevel switch
        {
            ThreatLevel.Critical => RecommendedAction.Block,
            ThreatLevel.High => riskScore >= 90 ? RecommendedAction.Block : RecommendedAction.Challenge,
            ThreatLevel.Medium => riskScore >= 60 ? RecommendedAction.Challenge : RecommendedAction.Throttle,
            ThreatLevel.Low => RecommendedAction.Monitor,
            _ => RecommendedAction.Allow
        };
    }

    /// <summary>
    /// Generates human-readable explanation of risk assessment
    /// </summary>
    private string GenerateExplanation(RiskAssessmentResult result)
    {
        var explanation = new List<string>();
        
        // Overall assessment
        explanation.Add($"Risk Score: {result.RiskScore:F1}/100 ({result.ThreatLevel})");
        
        // Threat factors
        if (result.ThreatScore.FinalThreatScore > 70)
        {
            explanation.Add($"High threat score ({result.ThreatScore.FinalThreatScore:F1}) indicates suspicious activity");
        }
        else if (result.ThreatScore.FinalThreatScore < 30)
        {
            explanation.Add($"Low threat score ({result.ThreatScore.FinalThreatScore:F1}) indicates normal activity");
        }

        // Trust factors
        if (result.TrustScore.FinalTrustScore > 70)
        {
            explanation.Add($"High trust score ({result.TrustScore.FinalTrustScore:F1}) indicates established reputation");
        }
        else if (result.TrustScore.FinalTrustScore < 30)
        {
            explanation.Add($"Low trust score ({result.TrustScore.FinalTrustScore:F1}) indicates limited history or negative indicators");
        }

        // Recommended action reasoning
        var actionReason = result.RecommendedAction switch
        {
            RecommendedAction.Block => "Immediate blocking recommended due to high risk",
            RecommendedAction.Challenge => "Additional verification recommended",
            RecommendedAction.Throttle => "Rate limiting recommended to reduce risk",
            RecommendedAction.Monitor => "Continued monitoring recommended",
            _ => "Normal processing can continue"
        };
        explanation.Add(actionReason);

        return string.Join(". ", explanation);
    }

    /// <summary>
    /// Identifies risk factors from threat assessment
    /// </summary>
    private List<string> IdentifyRiskFactors(ThreatScoreResult threatResult, ThreatScoringContext context)
    {
        var factors = new List<string>();

        // High-scoring components
        if (threatResult.BaseScore > 40)
            factors.Add($"Known threat indicators (score: {threatResult.BaseScore:F1})");
        
        if (threatResult.BehavioralScore > 30)
            factors.Add($"Suspicious behavior patterns (score: {threatResult.BehavioralScore:F1})");
        
        if (threatResult.GeographicScore > 25)
            factors.Add($"Geographic risk indicators (score: {threatResult.GeographicScore:F1})");
        
        if (threatResult.PatternScore > 35)
            factors.Add($"Threat pattern matches (score: {threatResult.PatternScore:F1})");
        
        if (threatResult.FrequencyScore > 30)
            factors.Add($"High request frequency (score: {threatResult.FrequencyScore:F1})");

        // Specific context factors
        if (context.IsKnownMalicious)
            factors.Add("IP is on known malicious list");
        
        if (context.BlocklistMatches > 0)
            factors.Add($"Found on {context.BlocklistMatches} blocklist(s)");
        
        if (context.PreviousIncidents > 0)
            factors.Add($"{context.PreviousIncidents} previous security incidents");

        return factors;
    }

    /// <summary>
    /// Identifies trust factors from trust assessment
    /// </summary>
    private List<string> IdentifyTrustFactors(TrustScoreResult trustResult, TrustScoringContext context)
    {
        var factors = new List<string>();

        // High-scoring trust components
        if (trustResult.HistoryScore > 60)
            factors.Add($"Positive historical behavior (score: {trustResult.HistoryScore:F1})");
        
        if (trustResult.ConsistencyScore > 60)
            factors.Add($"Consistent behavior patterns (score: {trustResult.ConsistencyScore:F1})");
        
        if (trustResult.AuthenticationScore > 50)
            factors.Add($"Good authentication history (score: {trustResult.AuthenticationScore:F1})");
        
        if (trustResult.ReputationScore > 50)
            factors.Add($"Positive reputation indicators (score: {trustResult.ReputationScore:F1})");

        // Specific context factors
        if (context.IsWhitelisted)
            factors.Add("IP is whitelisted");
        
        if (context.IsKnownGood)
            factors.Add("IP is on known good list");
        
        if (context.DaysSinceFirstSeen > 90)
            factors.Add($"Long-term presence ({context.DaysSinceFirstSeen} days)");
        
        if (context.TotalRequests > 1000 && context.SecurityIncidents == 0)
            factors.Add($"Clean history with {context.TotalRequests} requests and no incidents");

        return factors;
    }

    /// <summary>
    /// Derives trust context from threat context when not provided separately
    /// </summary>
    private TrustScoringContext DeriveTrustContext(ThreatScoringContext threatContext)
    {
        var trustContext = new TrustScoringContext
        {
            IPAddress = threatContext.IPAddress,
            ExistingRecord = threatContext.ExistingRecord,
            BehaviorProfile = threatContext.BehaviorProfile
        };

        // Derive trust metrics from existing record
        if (threatContext.ExistingRecord != null)
        {
            var record = threatContext.ExistingRecord;
            trustContext.DaysSinceFirstSeen = (DateTime.UtcNow - record.FirstSeen).Days;
            trustContext.TotalRequests = record.RequestCount;
            trustContext.BlockedRequests = record.BlockedCount;
            
            // Estimate other metrics (would be better to track these separately)
            trustContext.SecurityIncidents = Math.Max(0, threatContext.PreviousIncidents);
        }

        return trustContext;
    }
}

/// <summary>
/// Interface for risk assessment engine
/// </summary>
public interface IRiskAssessmentEngine
{
    /// <summary>
    /// Performs comprehensive risk assessment with separate threat and trust contexts
    /// </summary>
    Task<RiskAssessmentResult> AssessRiskAsync(ThreatScoringContext threatContext, TrustScoringContext trustContext);

    /// <summary>
    /// Performs risk assessment with single context (derives trust from threat data)
    /// </summary>
    Task<RiskAssessmentResult> AssessRiskAsync(ThreatScoringContext context);
}

/// <summary>
/// Configuration options for risk assessment
/// </summary>
public class RiskAssessmentOptions
{
    /// <summary>
    /// Weight for threat score in risk calculation
    /// </summary>
    public double ThreatWeight { get; set; } = 0.7;

    /// <summary>
    /// Weight for trust score in risk calculation
    /// </summary>
    public double TrustWeight { get; set; } = 0.3;

    /// <summary>
    /// Amplifier for high-risk scenarios (high threat + low trust)
    /// </summary>
    public double HighRiskAmplifier { get; set; } = 1.2;

    /// <summary>
    /// Mitigator for low-risk scenarios (low threat + high trust)
    /// </summary>
    public double LowRiskMitigator { get; set; } = 0.8;

    /// <summary>
    /// Risk score threshold for critical threat level
    /// </summary>
    public double CriticalThreshold { get; set; } = 85.0;

    /// <summary>
    /// Risk score threshold for high threat level
    /// </summary>
    public double HighThreshold { get; set; } = 70.0;

    /// <summary>
    /// Risk score threshold for medium threat level
    /// </summary>
    public double MediumThreshold { get; set; } = 50.0;

    /// <summary>
    /// Risk score threshold for low threat level
    /// </summary>
    public double LowThreshold { get; set; } = 25.0;
}