using SecurityFramework.Core.Models;
using Microsoft.Extensions.Logging;

namespace SecurityFramework.Core.Services;

/// <summary>
/// Advanced threat scoring engine with machine learning-inspired algorithms
/// </summary>
public class ThreatScoringEngine : IThreatScoringEngine
{
    private readonly ILogger<ThreatScoringEngine> _logger;
    private readonly ThreatScoringOptions _options;

    public ThreatScoringEngine(ILogger<ThreatScoringEngine> logger, ThreatScoringOptions options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Calculates comprehensive threat score using multiple algorithms
    /// </summary>
    public async Task<ThreatScoreResult> CalculateThreatScoreAsync(ThreatScoringContext context)
    {
        var startTime = DateTime.UtcNow;
        
        try
        {
            // Initialize result
            var result = new ThreatScoreResult
            {
                IPAddress = context.IPAddress,
                CalculatedAt = startTime
            };

            // Calculate base threat score
            result.BaseScore = CalculateBaseThreatScore(context);

            // Calculate behavioral score
            result.BehavioralScore = CalculateBehavioralScore(context);

            // Calculate geographic score
            result.GeographicScore = CalculateGeographicScore(context);

            // Calculate temporal score
            result.TemporalScore = CalculateTemporalScore(context);

            // Calculate pattern-based score
            result.PatternScore = CalculatePatternScore(context);

            // Calculate frequency-based score
            result.FrequencyScore = CalculateFrequencyScore(context);

            // Calculate reputation score
            result.ReputationScore = await CalculateReputationScoreAsync(context);

            // Combine scores using weighted algorithm
            result.CombinedScore = CombineScores(result);

            // Apply contextual adjustments
            result.AdjustedScore = ApplyContextualAdjustments(result, context);

            // Final threat score with bounds checking
            result.FinalThreatScore = Math.Max(0, Math.Min(100, result.AdjustedScore));

            // Calculate confidence
            result.Confidence = CalculateConfidence(result, context);

            // Record processing time
            result.ProcessingTimeMs = (DateTime.UtcNow - startTime).TotalMilliseconds;

            _logger.LogDebug("Threat score calculated for {IPAddress}: {Score} (confidence: {Confidence}%)", 
                context.IPAddress, result.FinalThreatScore, result.Confidence);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calculating threat score for {IPAddress}", context.IPAddress);
            
            // Return safe default on error
            return new ThreatScoreResult
            {
                IPAddress = context.IPAddress,
                FinalThreatScore = _options.DefaultThreatScore,
                Confidence = 50.0,
                ProcessingTimeMs = (DateTime.UtcNow - startTime).TotalMilliseconds,
                HasError = true,
                ErrorMessage = ex.Message
            };
        }
    }

    /// <summary>
    /// Calculates trust score using multiple trust indicators
    /// </summary>
    public async Task<TrustScoreResult> CalculateTrustScoreAsync(TrustScoringContext context)
    {
        var startTime = DateTime.UtcNow;

        try
        {
            var result = new TrustScoreResult
            {
                IPAddress = context.IPAddress,
                CalculatedAt = startTime
            };

            // Calculate base trust factors
            result.HistoryScore = CalculateHistoryTrustScore(context);
            result.ConsistencyScore = CalculateConsistencyScore(context);
            result.AuthenticationScore = CalculateAuthenticationScore(context);
            result.ReputationScore = await CalculateReputationTrustScoreAsync(context);
            result.BehaviorScore = CalculateBehaviorTrustScore(context);

            // Combine trust scores
            result.CombinedScore = CombineTrustScores(result);

            // Apply trust adjustments
            result.AdjustedScore = ApplyTrustAdjustments(result, context);

            // Final trust score
            result.FinalTrustScore = Math.Max(0, Math.Min(100, result.AdjustedScore));

            // Calculate confidence
            result.Confidence = CalculateTrustConfidence(result, context);

            result.ProcessingTimeMs = (DateTime.UtcNow - startTime).TotalMilliseconds;

            _logger.LogDebug("Trust score calculated for {IPAddress}: {Score} (confidence: {Confidence}%)", 
                context.IPAddress, result.FinalTrustScore, result.Confidence);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calculating trust score for {IPAddress}", context.IPAddress);
            
            return new TrustScoreResult
            {
                IPAddress = context.IPAddress,
                FinalTrustScore = _options.DefaultTrustScore,
                Confidence = 50.0,
                ProcessingTimeMs = (DateTime.UtcNow - startTime).TotalMilliseconds,
                HasError = true,
                ErrorMessage = ex.Message
            };
        }
    }

    #region Threat Scoring Components

    /// <summary>
    /// Calculates base threat score from fundamental indicators
    /// </summary>
    private double CalculateBaseThreatScore(ThreatScoringContext context)
    {
        var score = 0.0;

        // Known malicious indicators
        if (context.IsKnownMalicious)
            score += 80.0;

        // Blocklist matches
        if (context.BlocklistMatches > 0)
            score += Math.Min(60.0, context.BlocklistMatches * 20.0);

        // Previous incidents
        if (context.PreviousIncidents > 0)
            score += Math.Min(40.0, context.PreviousIncidents * 5.0);

        // Failed authentication attempts
        if (context.FailedAuthAttempts > 0)
            score += Math.Min(30.0, context.FailedAuthAttempts * 3.0);

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates behavioral threat score
    /// </summary>
    private double CalculateBehavioralScore(ThreatScoringContext context)
    {
        if (context.BehaviorProfile == null)
            return 0.0;

        var score = 0.0;
        var profile = context.BehaviorProfile;

        // High request frequency anomaly
        if (profile.RequestFrequency > _options.HighFrequencyThreshold)
            score += 25.0;

        // User agent variations (bot indicator)
        if (profile.UserAgentVariations > _options.MaxUserAgentVariations)
            score += 20.0;

        // Geographic inconsistency
        if (profile.GeographicConsistency < _options.MinGeographicConsistency)
            score += 15.0;

        // Time pattern inconsistency
        if (profile.TimePatternConsistency < _options.MinTimeConsistency)
            score += 10.0;

        // High error rate
        if (profile.ErrorRate > _options.MaxErrorRate)
            score += 15.0;

        // Anomaly score from ML analysis
        score += profile.AnomalyScore * 0.3;

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates geographic threat score
    /// </summary>
    private double CalculateGeographicScore(ThreatScoringContext context)
    {
        if (context.GeographicInfo == null)
            return 0.0;

        var score = 0.0;
        var geo = context.GeographicInfo;

        // High-risk countries
        if (geo.IsHighRiskLocation)
            score += 30.0;

        // VPN/Proxy indicators
        if (geo.IsVPNOrProxy)
            score += 25.0;

        // Tor exit nodes
        if (geo.IsTorExitNode)
            score += 40.0;

        // Geographic distance from normal patterns
        if (geo.DistanceFromNormal.HasValue && geo.DistanceFromNormal.Value > _options.MaxGeographicDistance)
            score += 20.0;

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates temporal threat score based on time patterns
    /// </summary>
    private double CalculateTemporalScore(ThreatScoringContext context)
    {
        var score = 0.0;
        var now = context.RequestTime ?? DateTime.UtcNow;

        // Off-hours access (higher risk)
        if (IsOffHours(now))
            score += 15.0;

        // Weekend access anomaly
        if (now.DayOfWeek == DayOfWeek.Saturday || now.DayOfWeek == DayOfWeek.Sunday)
            score += 10.0;

        // Rapid successive requests
        if (context.RequestInterval.HasValue && context.RequestInterval.Value.TotalSeconds < 1.0)
            score += 20.0;

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates pattern-based threat score
    /// </summary>
    private double CalculatePatternScore(ThreatScoringContext context)
    {
        if (context.PatternMatches == null || !context.PatternMatches.Any())
            return 0.0;

        var score = 0.0;

        foreach (var match in context.PatternMatches)
        {
            // Weight by pattern confidence and severity
            var patternScore = match.Score * (match.Confidence / 100.0);
            score = Math.Max(score, patternScore); // Use highest scoring pattern
        }

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates frequency-based threat score
    /// </summary>
    private double CalculateFrequencyScore(ThreatScoringContext context)
    {
        var score = 0.0;

        // Request rate analysis
        if (context.RequestsPerMinute > _options.MaxRequestsPerMinute)
            score += 30.0;

        if (context.RequestsPerHour > _options.MaxRequestsPerHour)
            score += 20.0;

        // Burst detection
        if (context.HasRequestBurst)
            score += 25.0;

        // Rate limit violations
        if (context.RateLimitViolations > 0)
            score += Math.Min(25.0, context.RateLimitViolations * 5.0);

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates reputation-based threat score
    /// </summary>
    private async Task<double> CalculateReputationScoreAsync(ThreatScoringContext context)
    {
        // This would integrate with external threat intelligence feeds
        // For now, return base reputation score
        var score = 0.0;

        if (context.ThreatIntelMatches != null)
        {
            foreach (var match in context.ThreatIntelMatches)
            {
                score += match.Severity switch
                {
                    ThreatSeverity.Critical => 50.0,
                    ThreatSeverity.High => 40.0,
                    ThreatSeverity.Medium => 25.0,
                    ThreatSeverity.Low => 15.0,
                    _ => 5.0
                };
            }
        }

        return Math.Min(100.0, score);
    }

    #endregion

    #region Trust Scoring Components

    /// <summary>
    /// Calculates trust score based on historical behavior
    /// </summary>
    private double CalculateHistoryTrustScore(TrustScoringContext context)
    {
        var score = _options.DefaultTrustScore;

        // Long positive history increases trust
        if (context.DaysSinceFirstSeen > 30)
            score += Math.Min(20.0, context.DaysSinceFirstSeen / 10.0);

        // Consistent good behavior
        if (context.TotalRequests > 100 && context.BlockedRequests == 0)
            score += 15.0;

        // Low incident rate
        var incidentRate = context.TotalRequests > 0 ? (double)context.SecurityIncidents / context.TotalRequests : 0;
        if (incidentRate < 0.01) // Less than 1% incident rate
            score += 10.0;

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates consistency-based trust score
    /// </summary>
    private double CalculateConsistencyScore(TrustScoringContext context)
    {
        var score = 0.0;

        if (context.BehaviorProfile != null)
        {
            // Geographic consistency
            score += context.BehaviorProfile.GeographicConsistency * 25.0;

            // Time pattern consistency
            score += context.BehaviorProfile.TimePatternConsistency * 15.0;

            // Low user agent variations
            if (context.BehaviorProfile.UserAgentVariations <= 3)
                score += 10.0;
        }

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates authentication-based trust score
    /// </summary>
    private double CalculateAuthenticationScore(TrustScoringContext context)
    {
        var score = 0.0;

        // Successful authentication history
        if (context.SuccessfulLogins > 0)
            score += Math.Min(25.0, context.SuccessfulLogins / 10.0);

        // Low failed authentication rate
        var totalAuthAttempts = context.SuccessfulLogins + context.FailedLogins;
        if (totalAuthAttempts > 0)
        {
            var successRate = (double)context.SuccessfulLogins / totalAuthAttempts;
            if (successRate > 0.9)
                score += 20.0;
        }

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates reputation-based trust score
    /// </summary>
    private async Task<double> CalculateReputationTrustScoreAsync(TrustScoringContext context)
    {
        var score = 0.0;

        // Positive reputation indicators
        if (context.IsKnownGood)
            score += 40.0;

        // Whitelist membership
        if (context.IsWhitelisted)
            score += 30.0;

        return Math.Min(100.0, score);
    }

    /// <summary>
    /// Calculates behavior-based trust score
    /// </summary>
    private double CalculateBehaviorTrustScore(TrustScoringContext context)
    {
        var score = 0.0;

        if (context.BehaviorProfile != null)
        {
            // Low anomaly score indicates trustworthy behavior
            score += (100.0 - context.BehaviorProfile.AnomalyScore) * 0.2;

            // Reasonable error rate
            if (context.BehaviorProfile.ErrorRate < 0.05) // Less than 5% errors
                score += 15.0;
        }

        return Math.Min(100.0, score);
    }

    #endregion

    #region Score Combination Logic

    /// <summary>
    /// Combines multiple threat scores using weighted algorithm
    /// </summary>
    private double CombineScores(ThreatScoreResult result)
    {
        var weights = _options.ThreatScoreWeights;
        
        return (result.BaseScore * weights.BaseWeight +
                result.BehavioralScore * weights.BehavioralWeight +
                result.GeographicScore * weights.GeographicWeight +
                result.TemporalScore * weights.TemporalWeight +
                result.PatternScore * weights.PatternWeight +
                result.FrequencyScore * weights.FrequencyWeight +
                result.ReputationScore * weights.ReputationWeight) / weights.TotalWeight;
    }

    /// <summary>
    /// Combines multiple trust scores using weighted algorithm
    /// </summary>
    private double CombineTrustScores(TrustScoreResult result)
    {
        var weights = _options.TrustScoreWeights;
        
        return (result.HistoryScore * weights.HistoryWeight +
                result.ConsistencyScore * weights.ConsistencyWeight +
                result.AuthenticationScore * weights.AuthenticationWeight +
                result.ReputationScore * weights.ReputationWeight +
                result.BehaviorScore * weights.BehaviorWeight) / weights.TotalWeight;
    }

    /// <summary>
    /// Applies contextual adjustments to threat score
    /// </summary>
    private double ApplyContextualAdjustments(ThreatScoreResult result, ThreatScoringContext context)
    {
        var score = result.CombinedScore;

        // Context-based multipliers
        if (context.IsHighValueTarget)
            score *= 1.2;

        if (context.IsInternalNetwork)
            score *= 0.8;

        if (context.HasValidBusinessJustification)
            score *= 0.7;

        return score;
    }

    /// <summary>
    /// Applies contextual adjustments to trust score
    /// </summary>
    private double ApplyTrustAdjustments(TrustScoreResult result, TrustScoringContext context)
    {
        var score = result.CombinedScore;

        // Verified business relationship
        if (context.IsVerifiedBusiness)
            score *= 1.2;

        // Long-term partnership
        if (context.IsLongTermPartner)
            score *= 1.1;

        return score;
    }

    #endregion

    #region Confidence Calculation

    /// <summary>
    /// Calculates confidence in threat score
    /// </summary>
    private double CalculateConfidence(ThreatScoreResult result, ThreatScoringContext context)
    {
        var confidence = 50.0; // Base confidence

        // More data points increase confidence
        var dataPoints = CountDataPoints(context);
        confidence += Math.Min(30.0, dataPoints * 2.0);

        // Recent data is more reliable
        if (context.LastSeenDaysAgo <= 1)
            confidence += 15.0;
        else if (context.LastSeenDaysAgo <= 7)
            confidence += 10.0;

        // Pattern matches increase confidence
        if (context.PatternMatches?.Any() == true)
            confidence += 10.0;

        return Math.Min(100.0, confidence);
    }

    /// <summary>
    /// Calculates confidence in trust score
    /// </summary>
    private double CalculateTrustConfidence(TrustScoreResult result, TrustScoringContext context)
    {
        var confidence = 50.0; // Base confidence

        // Longer history increases confidence
        if (context.DaysSinceFirstSeen > 90)
            confidence += 25.0;
        else if (context.DaysSinceFirstSeen > 30)
            confidence += 15.0;

        // More interactions increase confidence
        if (context.TotalRequests > 1000)
            confidence += 20.0;
        else if (context.TotalRequests > 100)
            confidence += 10.0;

        return Math.Min(100.0, confidence);
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Determines if the request time is during off-hours
    /// </summary>
    private bool IsOffHours(DateTime requestTime)
    {
        var hour = requestTime.Hour;
        return hour < _options.BusinessStartHour || hour >= _options.BusinessEndHour;
    }

    /// <summary>
    /// Counts available data points for scoring
    /// </summary>
    private int CountDataPoints(ThreatScoringContext context)
    {
        var count = 0;
        
        if (context.BehaviorProfile != null) count++;
        if (context.GeographicInfo != null) count++;
        if (context.PatternMatches?.Any() == true) count++;
        if (context.ThreatIntelMatches?.Any() == true) count++;
        if (context.PreviousIncidents > 0) count++;
        if (context.RequestsPerMinute > 0) count++;
        
        return count;
    }

    #endregion
}

/// <summary>
/// Interface for threat scoring engine
/// </summary>
public interface IThreatScoringEngine
{
    /// <summary>
    /// Calculates comprehensive threat score
    /// </summary>
    Task<ThreatScoreResult> CalculateThreatScoreAsync(ThreatScoringContext context);

    /// <summary>
    /// Calculates trust score
    /// </summary>
    Task<TrustScoreResult> CalculateTrustScoreAsync(TrustScoringContext context);
}