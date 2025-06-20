# SecurityFramework Scoring Algorithms

## Overview

The SecurityFramework employs sophisticated scoring algorithms to quantify security threats in real-time. This document provides comprehensive coverage of all scoring methodologies, mathematical formulations, implementation details, and optimization techniques used for threat assessment.

## Table of Contents

1. [Scoring Architecture](#scoring-architecture)
2. [IP-Based Threat Scoring](#ip-based-threat-scoring)
3. [Pattern-Based Scoring](#pattern-based-scoring)
4. [Behavioral Analysis Scoring](#behavioral-analysis-scoring)
5. [Parameter Jacking Risk Scoring](#parameter-jacking-risk-scoring)
6. [Geographic Risk Scoring](#geographic-risk-scoring)
7. [Machine Learning Integration](#machine-learning-integration)
8. [Composite Scoring Algorithms](#composite-scoring-algorithms)
9. [Real-Time Scoring Optimization](#real-time-scoring-optimization)
10. [Scoring Calibration](#scoring-calibration)
11. [Algorithm Performance](#algorithm-performance)
12. [Validation and Testing](#validation-and-testing)

## Scoring Architecture

### Core Scoring Principles

#### 1. Multi-Dimensional Assessment
The SecurityFramework uses multiple independent scoring dimensions that are combined using weighted algorithms:

```
Overall Threat Score = Σ(Wi × Si × Ci)
```

Where:
- Wi = Weight for scoring dimension i
- Si = Score for dimension i (0-100)
- Ci = Confidence factor for dimension i (0-1)

#### 2. Scoring Dimensions
```csharp
public enum ScoringDimension
{
    IPReputation,       // Weight: 0.25
    PatternMatching,    // Weight: 0.30
    BehavioralAnalysis, // Weight: 0.20
    ParameterJacking,   // Weight: 0.15
    GeographicRisk,     // Weight: 0.10
    MachineLearning     // Weight: 0.35 (when enabled)
}
```

#### 3. Confidence Factors
Confidence factors adjust scores based on data quality and quantity:

```csharp
public class ConfidenceCalculator
{
    public double CalculateConfidence(ScoringContext context)
    {
        var factors = new Dictionary<string, double>
        {
            ["DataAge"] = CalculateDataAgeFactor(context.DataAge),
            ["SampleSize"] = CalculateSampleSizeFactor(context.SampleSize),
            ["DataQuality"] = CalculateDataQualityFactor(context.DataQuality),
            ["ConsistencyScore"] = CalculateConsistencyFactor(context.Consistency)
        };
        
        // Geometric mean of all factors
        return Math.Pow(factors.Values.Aggregate(1.0, (a, b) => a * b), 1.0 / factors.Count);
    }
}
```

### Scoring Pipeline Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Request Input     │───▶│   Data Extraction   │───▶│   Feature Vector    │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                      │
                                      ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Final Threat Score │◀───│  Composite Scoring  │◀───│ Parallel Scorers    │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                      ▲
                                      │
                           ┌─────────────────────┐
                           │   Confidence        │
                           │   Calculation       │
                           └─────────────────────┘
```

## IP-Based Threat Scoring

### IP Reputation Scoring Algorithm

#### Base Reputation Calculation
```csharp
public class IPReputationScorer
{
    public async Task<IPReputationScore> CalculateIPReputationAsync(string ipAddress)
    {
        var score = new IPReputationScore();
        
        // Historical incident weighting
        score.HistoricalScore = CalculateHistoricalScore(ipAddress);
        
        // Behavioral pattern analysis
        score.BehavioralScore = await CalculateBehavioralScoreAsync(ipAddress);
        
        // External reputation feeds
        score.ExternalScore = await GetExternalReputationAsync(ipAddress);
        
        // Geographic risk assessment
        score.GeographicScore = await CalculateGeographicRiskAsync(ipAddress);
        
        // Temporal decay factor
        score.DecayFactor = CalculateDecayFactor(ipAddress);
        
        return CalculateOverallIPScore(score);
    }
    
    private double CalculateHistoricalScore(string ipAddress)
    {
        var incidents = GetHistoricalIncidents(ipAddress);
        
        if (!incidents.Any()) return 0;
        
        var weightedScore = incidents.Sum(incident => 
        {
            var timeWeight = CalculateTimeWeight(incident.Timestamp);
            var severityWeight = GetSeverityWeight(incident.Severity);
            return incident.ThreatScore * timeWeight * severityWeight;
        });
        
        // Normalize to 0-100 scale
        return Math.Min(weightedScore / incidents.Count, 100);
    }
    
    private double CalculateTimeWeight(DateTime incidentTime)
    {
        var daysSince = (DateTime.UtcNow - incidentTime).TotalDays;
        
        // Exponential decay with half-life of 30 days
        return Math.Exp(-0.693 * daysSince / 30.0);
    }
}
```

#### Behavioral Pattern Scoring
```csharp
public class BehavioralPatternScorer
{
    public async Task<double> CalculateBehavioralScoreAsync(string ipAddress)
    {
        var metrics = await GetBehavioralMetricsAsync(ipAddress);
        
        var scores = new Dictionary<string, double>
        {
            ["RequestFrequency"] = ScoreRequestFrequency(metrics.RequestFrequency),
            ["RequestTiming"] = ScoreRequestTiming(metrics.RequestTimings),
            ["EndpointDiversity"] = ScoreEndpointDiversity(metrics.EndpointAccess),
            ["UserAgentConsistency"] = ScoreUserAgentPattern(metrics.UserAgents),
            ["SessionBehavior"] = ScoreSessionBehavior(metrics.SessionPatterns)
        };
        
        // Weighted average with adaptive weights
        var weights = CalculateAdaptiveWeights(metrics);
        return scores.Sum(kvp => kvp.Value * weights[kvp.Key]);
    }
    
    private double ScoreRequestFrequency(RequestFrequencyMetrics metrics)
    {
        var baseline = metrics.BaselineFrequency;
        var current = metrics.CurrentFrequency;
        
        if (baseline == 0) return current > 100 ? 75 : 0; // No baseline, use threshold
        
        var ratio = current / baseline;
        
        return ratio switch
        {
            > 10 => 90,   // 10x normal = very suspicious
            > 5 => 70,    // 5x normal = suspicious
            > 3 => 40,    // 3x normal = elevated
            > 2 => 20,    // 2x normal = slight concern
            _ => 0        // Normal or below normal
        };
    }
    
    private double ScoreRequestTiming(List<TimeSpan> intervals)
    {
        if (intervals.Count < 10) return 0; // Insufficient data
        
        // Calculate coefficient of variation
        var mean = intervals.Average(i => i.TotalMilliseconds);
        var variance = intervals.Average(i => Math.Pow(i.TotalMilliseconds - mean, 2));
        var stdDev = Math.Sqrt(variance);
        var cv = stdDev / mean;
        
        // Low CV indicates robotic behavior
        return cv switch
        {
            < 0.1 => 80,  // Very consistent = likely bot
            < 0.2 => 50,  // Somewhat consistent = possible bot
            < 0.5 => 20,  // Moderately consistent = suspicious
            _ => 0        // High variation = likely human
        };
    }
}
```

### Trust Score Calculation
```csharp
public class TrustScoreCalculator
{
    public double CalculateTrustScore(IPSecurityRecord record)
    {
        var factors = new TrustFactors
        {
            LongevityFactor = CalculateLongevityFactor(record.FirstSeenAt),
            ConsistencyFactor = CalculateConsistencyFactor(record),
            ViolationFactor = CalculateViolationFactor(record.ThreatIncidents),
            WhitelistFactor = CalculateWhitelistFactor(record.IPAddress),
            ReputationFactor = CalculatePositiveReputationFactor(record)
        };
        
        // Trust score is inverse of threat indicators
        var baseTrust = 100 - record.ThreatScore;
        
        // Apply positive trust factors
        var enhancedTrust = baseTrust * 
            factors.LongevityFactor * 
            factors.ConsistencyFactor * 
            factors.WhitelistFactor * 
            factors.ReputationFactor;
            
        // Apply negative trust factors
        var adjustedTrust = enhancedTrust * (1 - factors.ViolationFactor);
        
        return Math.Max(0, Math.Min(100, adjustedTrust));
    }
    
    private double CalculateLongevityFactor(DateTime firstSeen)
    {
        var daysSince = (DateTime.UtcNow - firstSeen).TotalDays;
        
        return daysSince switch
        {
            > 365 => 1.3,   // Long history = more trust
            > 180 => 1.2,   // Moderate history
            > 90 => 1.1,    // Some history
            > 30 => 1.0,    // Recent but established
            _ => 0.8        // Very new = less trust
        };
    }
}
```

## Pattern-Based Scoring

### Pattern Match Scoring Algorithm

#### Individual Pattern Scoring
```csharp
public class PatternMatchScorer
{
    public PatternMatchScore CalculatePatternScore(PatternMatch match, ThreatPattern pattern)
    {
        var baseScore = pattern.ThreatMultiplier;
        var confidence = pattern.Confidence;
        var context = match.Context;
        
        // Apply context-based adjustments
        var contextMultiplier = CalculateContextMultiplier(match, pattern);
        var riskMultiplier = CalculateRiskMultiplier(match.MatchedValue, pattern);
        var frequencyPenalty = CalculateFrequencyPenalty(pattern.Name);
        
        var adjustedScore = baseScore * contextMultiplier * riskMultiplier * frequencyPenalty;
        
        return new PatternMatchScore
        {
            BaseScore = baseScore,
            AdjustedScore = Math.Min(100, adjustedScore),
            Confidence = confidence,
            ContextMultiplier = contextMultiplier,
            RiskMultiplier = riskMultiplier,
            FrequencyPenalty = frequencyPenalty
        };
    }
    
    private double CalculateContextMultiplier(PatternMatch match, ThreatPattern pattern)
    {
        var multiplier = 1.0;
        
        // Location context adjustments
        multiplier *= match.MatchLocation switch
        {
            "body" => 1.2,      // Body content is higher risk
            "header" => 1.1,    // Headers are moderately risky
            "queryParam" => 1.0, // Query params are baseline
            "url" => 0.9,       // URL paths are slightly lower risk
            _ => 1.0
        };
        
        // Pattern category adjustments
        multiplier *= pattern.Category switch
        {
            "SQLInjection" => IsDataEndpoint(match) ? 1.5 : 1.0,
            "XSS" => IsUserContentEndpoint(match) ? 1.3 : 1.0,
            "PathTraversal" => IsFileEndpoint(match) ? 1.4 : 1.0,
            _ => 1.0
        };
        
        return multiplier;
    }
    
    private double CalculateRiskMultiplier(string matchedValue, ThreatPattern pattern)
    {
        var riskFactors = new List<double>();
        
        // Length-based risk assessment
        riskFactors.Add(CalculateLengthRisk(matchedValue, pattern.Category));
        
        // Complexity-based risk assessment
        riskFactors.Add(CalculateComplexityRisk(matchedValue));
        
        // Encoding detection
        riskFactors.Add(CalculateEncodingRisk(matchedValue));
        
        // Return maximum risk factor
        return riskFactors.Max();
    }
}
```

#### Multi-Pattern Aggregation
```csharp
public class MultiPatternAggregator
{
    public AggregatedPatternScore AggregatePatternScores(List<PatternMatchScore> scores)
    {
        if (!scores.Any()) return AggregatedPatternScore.Zero;
        
        // Group by pattern category
        var categoryScores = scores
            .GroupBy(s => s.PatternCategory)
            .ToDictionary(g => g.Key, g => g.ToList());
            
        var aggregatedScores = new Dictionary<string, double>();
        
        foreach (var category in categoryScores)
        {
            aggregatedScores[category.Key] = AggregateScoresForCategory(category.Value);
        }
        
        // Calculate overall pattern score
        var overallScore = CalculateOverallPatternScore(aggregatedScores);
        var confidence = CalculateAggregateConfidence(scores);
        
        return new AggregatedPatternScore
        {
            OverallScore = overallScore,
            CategoryScores = aggregatedScores,
            Confidence = confidence,
            MatchCount = scores.Count,
            HighestIndividualScore = scores.Max(s => s.AdjustedScore)
        };
    }
    
    private double AggregateScoresForCategory(List<PatternMatchScore> categoryScores)
    {
        // Use logarithmic aggregation to prevent score inflation
        var weightedSum = categoryScores.Sum(s => s.AdjustedScore * s.Confidence);
        var totalWeight = categoryScores.Sum(s => s.Confidence);
        
        if (totalWeight == 0) return 0;
        
        var averageScore = weightedSum / totalWeight;
        
        // Apply diminishing returns for multiple matches
        var diminishingFactor = 1 - Math.Exp(-categoryScores.Count / 3.0);
        
        return averageScore * diminishingFactor;
    }
}
```

### ReDoS Prevention Scoring
```csharp
public class ReDoSPreventionScorer
{
    public ReDoSRiskScore AssessReDoSRisk(string pattern, string input)
    {
        var riskFactors = new Dictionary<string, double>
        {
            ["NestedQuantifiers"] = DetectNestedQuantifiers(pattern),
            ["AlternationWithQuantifiers"] = DetectAlternationWithQuantifiers(pattern),
            ["InputLength"] = CalculateInputLengthRisk(input),
            ["RepetitiveInput"] = DetectRepetitiveInput(input),
            ["BacktrackingPotential"] = CalculateBacktrackingPotential(pattern, input)
        };
        
        var overallRisk = riskFactors.Values.Max(); // Use maximum risk
        
        return new ReDoSRiskScore
        {
            OverallRisk = overallRisk,
            RiskFactors = riskFactors,
            IsHighRisk = overallRisk > 0.7,
            RecommendedTimeout = CalculateRecommendedTimeout(overallRisk)
        };
    }
    
    private double DetectNestedQuantifiers(string pattern)
    {
        // Detect patterns like (a+)+ or (a*)* which are ReDoS vulnerable
        var nestedQuantifierPattern = @"\([^)]*[+*]\)[+*]";
        var matches = Regex.Matches(pattern, nestedQuantifierPattern);
        
        return Math.Min(1.0, matches.Count * 0.5);
    }
}
```

## Behavioral Analysis Scoring

### Anomaly Detection Algorithms

#### Statistical Anomaly Detection
```csharp
public class StatisticalAnomalyDetector
{
    public AnomalyScore DetectAnomalies(BehaviorProfile baseline, CurrentBehavior current)
    {
        var anomalyScores = new Dictionary<string, double>
        {
            ["RequestFrequency"] = DetectFrequencyAnomaly(baseline.RequestFrequency, current.RequestFrequency),
            ["SessionDuration"] = DetectDurationAnomaly(baseline.SessionDuration, current.SessionDuration),
            ["EndpointAccess"] = DetectEndpointAnomaly(baseline.EndpointAccess, current.EndpointAccess),
            ["TimingPattern"] = DetectTimingAnomaly(baseline.TimingPattern, current.TimingPattern),
            ["GeographicPattern"] = DetectGeographicAnomaly(baseline.Geographic, current.Geographic)
        };
        
        var overallScore = CalculateOverallAnomalyScore(anomalyScores);
        
        return new AnomalyScore
        {
            OverallScore = overallScore,
            ComponentScores = anomalyScores,
            Confidence = CalculateAnomalyConfidence(baseline, current),
            AnomalyType = DetermineAnomalyType(anomalyScores)
        };
    }
    
    private double DetectFrequencyAnomaly(FrequencyBaseline baseline, double currentFrequency)
    {
        if (baseline.SampleCount < 10) return 0; // Insufficient baseline data
        
        // Use modified Z-score for outlier detection
        var median = baseline.MedianFrequency;
        var mad = baseline.MedianAbsoluteDeviation;
        
        if (mad == 0) return currentFrequency > median * 2 ? 80 : 0;
        
        var modifiedZScore = 0.6745 * (currentFrequency - median) / mad;
        
        return Math.Abs(modifiedZScore) switch
        {
            > 3.5 => 90,  // Very strong outlier
            > 3.0 => 70,  // Strong outlier
            > 2.5 => 50,  // Moderate outlier
            > 2.0 => 30,  // Mild outlier
            _ => 0        // Within normal range
        };
    }
    
    private double DetectTimingAnomaly(TimingBaseline baseline, List<TimeSpan> currentTimings)
    {
        if (currentTimings.Count < 5) return 0;
        
        var currentMean = currentTimings.Average(t => t.TotalMilliseconds);
        var currentStdDev = CalculateStandardDeviation(currentTimings.Select(t => t.TotalMilliseconds));
        
        // Compare with baseline timing statistics
        var meanDeviation = Math.Abs(currentMean - baseline.MeanInterval) / baseline.StdDevInterval;
        var variabilityChange = Math.Abs(currentStdDev - baseline.StdDevInterval) / baseline.StdDevInterval;
        
        var anomalyScore = Math.Max(
            Math.Min(meanDeviation * 25, 100),     // Mean shift detection
            Math.Min(variabilityChange * 30, 100)  // Variability change detection
        );
        
        return anomalyScore;
    }
}
```

#### Machine Learning-Based Anomaly Detection
```csharp
public class MLAnomalyDetector
{
    private readonly IsolationForest _isolationForest;
    private readonly OneClassSVM _oneClassSVM;
    
    public async Task<MLAnomalyScore> DetectMLAnomaliesAsync(FeatureVector features)
    {
        var isolationScore = await _isolationForest.ScoreAsync(features);
        var svmScore = await _oneClassSVM.ScoreAsync(features);
        
        // Ensemble scoring
        var ensembleScore = (isolationScore * 0.6) + (svmScore * 0.4);
        
        return new MLAnomalyScore
        {
            EnsembleScore = ensembleScore,
            IsolationForestScore = isolationScore,
            OneClassSVMScore = svmScore,
            Confidence = CalculateMLConfidence(features),
            FeatureImportance = GetFeatureImportance(features)
        };
    }
    
    private FeatureVector ExtractFeatures(RequestContext context, IPSecurityRecord record)
    {
        return new FeatureVector
        {
            Features = new Dictionary<string, double>
            {
                ["RequestsPerHour"] = CalculateRequestsPerHour(record),
                ["UniqueEndpoints"] = CalculateUniqueEndpoints(record),
                ["AverageResponseTime"] = CalculateAverageResponseTime(record),
                ["ErrorRate"] = CalculateErrorRate(record),
                ["SessionDuration"] = CalculateSessionDuration(record),
                ["GeographicConsistency"] = CalculateGeographicConsistency(record),
                ["UserAgentEntropy"] = CalculateUserAgentEntropy(record),
                ["RequestSizeVariation"] = CalculateRequestSizeVariation(record),
                ["TimingRegularity"] = CalculateTimingRegularity(record),
                ["ParameterDiversity"] = CalculateParameterDiversity(record)
            }
        };
    }
}
```

### Behavioral Baseline Establishment
```csharp
public class BehavioralBaselineBuilder
{
    public async Task<BehaviorProfile> BuildBaselineAsync(string identifier, TimeSpan observationPeriod)
    {
        var observations = await GetObservationsAsync(identifier, observationPeriod);
        
        if (observations.Count < MinimumObservations)
            return BehaviorProfile.InsufficientData;
            
        var profile = new BehaviorProfile
        {
            RequestFrequency = CalculateFrequencyProfile(observations),
            SessionPattern = CalculateSessionProfile(observations),
            EndpointAccess = CalculateEndpointProfile(observations),
            TimingPattern = CalculateTimingProfile(observations),
            GeographicPattern = CalculateGeographicProfile(observations),
            UserAgentPattern = CalculateUserAgentProfile(observations),
            ParameterPattern = CalculateParameterProfile(observations)
        };
        
        profile.Confidence = CalculateBaselineConfidence(observations);
        profile.ExpiresAt = DateTime.UtcNow.Add(BaselineValidityPeriod);
        
        return profile;
    }
    
    private FrequencyProfile CalculateFrequencyProfile(List<BehaviorObservation> observations)
    {
        var hourlyRequests = observations
            .GroupBy(o => o.Timestamp.Hour)
            .ToDictionary(g => g.Key, g => g.Count());
            
        var dailyRequests = observations
            .GroupBy(o => o.Timestamp.Date)
            .Select(g => g.Count())
            .ToList();
            
        return new FrequencyProfile
        {
            HourlyDistribution = hourlyRequests,
            MeanDailyRequests = dailyRequests.Average(),
            StdDevDailyRequests = CalculateStandardDeviation(dailyRequests.Cast<double>()),
            PeakHours = IdentifyPeakHours(hourlyRequests),
            BaselineEstablishedAt = DateTime.UtcNow
        };
    }
}
```

## Parameter Jacking Risk Scoring

### Sequential Access Detection
```csharp
public class SequentialAccessDetector
{
    public SequentialAccessScore AnalyzeSequentialAccess(List<ParameterAccess> accesses)
    {
        if (accesses.Count < 3) return SequentialAccessScore.InsufficientData;
        
        var sequences = DetectSequences(accesses);
        var riskScore = CalculateSequentialRisk(sequences);
        
        return new SequentialAccessScore
        {
            RiskScore = riskScore,
            DetectedSequences = sequences,
            Confidence = CalculateSequenceConfidence(sequences),
            IsSequentialAccess = riskScore > 60
        };
    }
    
    private List<AccessSequence> DetectSequences(List<ParameterAccess> accesses)
    {
        var sequences = new List<AccessSequence>();
        
        // Group by parameter name and user
        var groups = accesses
            .GroupBy(a => new { a.ParameterName, a.UserId })
            .Where(g => g.Count() >= 3);
            
        foreach (var group in groups)
        {
            var sortedAccesses = group.OrderBy(a => a.AccessTime).ToList();
            var sequence = AnalyzeSequencePattern(sortedAccesses);
            
            if (sequence.IsSequential)
                sequences.Add(sequence);
        }
        
        return sequences;
    }
    
    private AccessSequence AnalyzeSequencePattern(List<ParameterAccess> accesses)
    {
        var values = accesses.Select(a => a.ParameterValue).ToList();
        var timings = accesses.Select(a => a.AccessTime).ToList();
        
        // Detect numeric sequences
        var numericSequence = DetectNumericSequence(values);
        
        // Detect timing patterns
        var timingPattern = AnalyzeTimingPattern(timings);
        
        return new AccessSequence
        {
            ParameterName = accesses.First().ParameterName,
            Values = values,
            IsSequential = numericSequence.IsSequential || timingPattern.IsRegular,
            SequenceType = DetermineSequenceType(numericSequence, timingPattern),
            RiskScore = CalculateSequenceRisk(numericSequence, timingPattern),
            TimeSpan = timings.Last() - timings.First()
        };
    }
    
    private NumericSequenceAnalysis DetectNumericSequence(List<string> values)
    {
        var numericValues = values
            .Select(v => int.TryParse(v, out var num) ? (int?)num : null)
            .Where(v => v.HasValue)
            .Select(v => v.Value)
            .ToList();
            
        if (numericValues.Count < 3) return NumericSequenceAnalysis.NotNumeric;
        
        // Check for arithmetic progression
        var differences = numericValues
            .Zip(numericValues.Skip(1), (a, b) => b - a)
            .ToList();
            
        var isArithmetic = differences.All(d => d == differences.First());
        
        if (isArithmetic)
        {
            return new NumericSequenceAnalysis
            {
                IsSequential = true,
                SequenceType = SequenceType.Arithmetic,
                CommonDifference = differences.First(),
                RiskScore = CalculateArithmeticSequenceRisk(differences.First(), numericValues.Count)
            };
        }
        
        // Check for other patterns
        return AnalyzeOtherPatterns(numericValues);
    }
    
    private double CalculateArithmeticSequenceRisk(int difference, int count)
    {
        // Higher risk for sequences with small differences and many values
        var differenceRisk = Math.Abs(difference) switch
        {
            1 => 90,        // Consecutive values = highest risk
            <= 5 => 70,     // Small gaps = high risk
            <= 10 => 50,    // Medium gaps = medium risk
            _ => 30         // Large gaps = lower risk
        };
        
        var countRisk = count switch
        {
            >= 10 => 20,    // Many values = additional risk
            >= 5 => 10,     // Several values = some additional risk
            _ => 0          // Few values = no additional risk
        };
        
        return Math.Min(100, differenceRisk + countRisk);
    }
}
```

### IDOR Risk Assessment
```csharp
public class IDORRiskAssessor
{
    public IDORRiskScore AssessIDORRisk(ParameterAccess access, UserContext userContext)
    {
        var riskFactors = new Dictionary<string, double>
        {
            ["OwnershipViolation"] = AssessOwnershipViolation(access, userContext),
            ["PrivilegeEscalation"] = AssessPrivilegeEscalation(access, userContext),
            ["DataSensitivity"] = AssessDataSensitivity(access.ResourceType),
            ["AccessPattern"] = AssessAccessPattern(access),
            ["UserProfile"] = AssessUserProfile(userContext)
        };
        
        var overallRisk = CalculateOverallIDORRisk(riskFactors);
        
        return new IDORRiskScore
        {
            OverallRisk = overallRisk,
            RiskFactors = riskFactors,
            IsHighRisk = overallRisk > 70,
            RequiresBlocking = overallRisk > 85,
            Confidence = CalculateIDORConfidence(access, userContext)
        };
    }
    
    private double AssessOwnershipViolation(ParameterAccess access, UserContext userContext)
    {
        if (string.IsNullOrEmpty(userContext.UserId))
            return 50; // No user context = moderate risk
            
        var resourceOwner = GetResourceOwner(access.ResourceId, access.ResourceType);
        
        if (resourceOwner == null)
            return 30; // Cannot determine ownership = lower risk
            
        if (resourceOwner.UserId != userContext.UserId)
        {
            // Check if user has legitimate access rights
            var hasLegitimateAccess = CheckLegitimateAccess(userContext, access);
            return hasLegitimateAccess ? 20 : 90; // No legitimate access = very high risk
        }
        
        return 0; // User owns the resource = no risk
    }
    
    private double AssessPrivilegeEscalation(ParameterAccess access, UserContext userContext)
    {
        var requiredRole = GetRequiredRole(access.ResourceType, access.Action);
        var userRoles = userContext.Roles;
        
        if (!userRoles.Any(r => r.Level >= requiredRole.Level))
        {
            var privilegeGap = requiredRole.Level - userRoles.Max(r => r.Level);
            
            return privilegeGap switch
            {
                >= 3 => 95,  // Significant privilege escalation
                2 => 80,     // Moderate privilege escalation
                1 => 60,     // Minor privilege escalation
                _ => 0       // No escalation
            };
        }
        
        return 0; // User has sufficient privileges
    }
}
```

## Geographic Risk Scoring

### Country-Based Risk Assessment
```csharp
public class GeographicRiskScorer
{
    private readonly Dictionary<string, CountryRiskProfile> _countryRiskProfiles;
    
    public GeographicRiskScore CalculateGeographicRisk(string ipAddress, GeolocationData geoData)
    {
        var countryRisk = CalculateCountryRisk(geoData.CountryCode);
        var infrastructureRisk = CalculateInfrastructureRisk(geoData);
        var distanceRisk = CalculateDistanceRisk(geoData, GetUserBaseline(geoData.UserId));
        var velocityRisk = CalculateVelocityRisk(geoData, GetRecentLocations(ipAddress));
        
        var overallRisk = AggregateGeographicRisks(
            countryRisk, infrastructureRisk, distanceRisk, velocityRisk);
            
        return new GeographicRiskScore
        {
            OverallRisk = overallRisk,
            CountryRisk = countryRisk,
            InfrastructureRisk = infrastructureRisk,
            DistanceRisk = distanceRisk,
            VelocityRisk = velocityRisk,
            Confidence = CalculateGeoConfidence(geoData)
        };
    }
    
    private double CalculateCountryRisk(string countryCode)
    {
        if (!_countryRiskProfiles.TryGetValue(countryCode, out var profile))
            return 40; // Unknown country = moderate risk
            
        var baseRisk = profile.ThreatScore;
        
        // Adjust for current threat intelligence
        var threatIntelAdjustment = GetCurrentThreatIntelligence(countryCode);
        
        return Math.Min(100, baseRisk + threatIntelAdjustment);
    }
    
    private double CalculateInfrastructureRisk(GeolocationData geoData)
    {
        var riskFactors = new Dictionary<string, double>
        {
            ["VPN"] = geoData.IsVPN ? 40 : 0,
            ["Proxy"] = geoData.IsProxy ? 30 : 0,
            ["Tor"] = geoData.IsTor ? 80 : 0,
            ["Hosting"] = geoData.IsHosting ? 25 : 0,
            ["Satellite"] = geoData.IsSatellite ? 15 : 0,
            ["Mobile"] = geoData.IsMobile ? -10 : 0  // Mobile is actually lower risk
        };
        
        // Use maximum risk factor with some aggregation
        var maxRisk = riskFactors.Values.Max();
        var aggregatedRisk = riskFactors.Values.Where(r => r > 0).Sum() * 0.3;
        
        return Math.Min(100, Math.Max(maxRisk, aggregatedRisk));
    }
    
    private double CalculateVelocityRisk(GeolocationData current, List<GeolocationData> recentLocations)
    {
        if (!recentLocations.Any()) return 0;
        
        var velocityViolations = new List<double>();
        
        foreach (var recent in recentLocations.Take(5)) // Check last 5 locations
        {
            var distance = CalculateDistance(current, recent);
            var timeDiff = (current.Timestamp - recent.Timestamp).TotalHours;
            
            if (timeDiff > 0 && timeDiff < 24) // Within 24 hours
            {
                var maxPossibleSpeed = timeDiff * 1000; // 1000 km/h max reasonable speed
                
                if (distance > maxPossibleSpeed)
                {
                    var impossibilityFactor = distance / maxPossibleSpeed;
                    velocityViolations.Add(Math.Min(100, impossibilityFactor * 50));
                }
            }
        }
        
        return velocityViolations.Any() ? velocityViolations.Max() : 0;
    }
}
```

### Geofencing Risk Assessment
```csharp
public class GeofencingRiskAssessor
{
    public GeofenceRiskScore AssessGeofenceRisk(GeolocationData location, UserProfile userProfile)
    {
        var allowedRegions = userProfile.AllowedRegions;
        var businessHours = userProfile.BusinessHours;
        var timeZone = userProfile.TimeZone;
        
        var regionRisk = AssessRegionRisk(location, allowedRegions);
        var timeRisk = AssessTimeRisk(location.Timestamp, businessHours, timeZone);
        var distanceRisk = AssessDistanceFromUsualLocations(location, userProfile.UsualLocations);
        
        return new GeofenceRiskScore
        {
            RegionRisk = regionRisk,
            TimeRisk = timeRisk,
            DistanceRisk = distanceRisk,
            OverallRisk = CalculateOverallGeofenceRisk(regionRisk, timeRisk, distanceRisk),
            IsViolation = regionRisk > 80 || timeRisk > 70
        };
    }
    
    private double AssessRegionRisk(GeolocationData location, List<AllowedRegion> allowedRegions)
    {
        if (!allowedRegions.Any()) return 0; // No restrictions = no risk
        
        foreach (var region in allowedRegions)
        {
            if (IsWithinRegion(location, region))
                return 0; // Within allowed region = no risk
        }
        
        // Not in any allowed region = high risk
        var nearestRegion = FindNearestAllowedRegion(location, allowedRegions);
        var distanceToNearest = CalculateDistance(location, nearestRegion.Center);
        
        return distanceToNearest switch
        {
            < 50 => 60,    // Close to allowed region = moderate risk
            < 200 => 80,   // Somewhat far = high risk
            _ => 95        // Very far = very high risk
        };
    }
}
```

## Machine Learning Integration

### ML Model Scoring Pipeline
```csharp
public class MLScoringPipeline
{
    private readonly Dictionary<string, IMLModel> _models;
    private readonly FeatureEngineer _featureEngineer;
    
    public async Task<MLThreatScore> ScoreAsync(RequestContext context)
    {
        var features = await _featureEngineer.ExtractFeaturesAsync(context);
        var modelScores = new Dictionary<string, double>();
        
        // Score with multiple models
        foreach (var model in _models)
        {
            try
            {
                var score = await model.Value.PredictAsync(features);
                modelScores[model.Key] = score;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("ML model {ModelName} failed: {Error}", model.Key, ex.Message);
            }
        }
        
        var ensembleScore = CalculateEnsembleScore(modelScores);
        
        return new MLThreatScore
        {
            EnsembleScore = ensembleScore,
            ModelScores = modelScores,
            Confidence = CalculateMLConfidence(modelScores),
            ModelCount = modelScores.Count,
            FeatureVector = features
        };
    }
    
    private double CalculateEnsembleScore(Dictionary<string, double> modelScores)
    {
        if (!modelScores.Any()) return 0;
        
        // Weighted average based on model performance
        var weights = GetModelWeights();
        var weightedSum = modelScores.Sum(kvp => 
            kvp.Value * weights.GetValueOrDefault(kvp.Key, 1.0));
        var totalWeight = modelScores.Sum(kvp => 
            weights.GetValueOrDefault(kvp.Key, 1.0));
            
        return weightedSum / totalWeight;
    }
    
    private Dictionary<string, double> GetModelWeights()
    {
        // Weights based on model validation performance
        return new Dictionary<string, double>
        {
            ["IsolationForest"] = 0.3,
            ["OneClassSVM"] = 0.25,
            ["AutoEncoder"] = 0.2,
            ["LSTM"] = 0.15,
            ["GradientBoosting"] = 0.1
        };
    }
}
```

### Feature Engineering
```csharp
public class FeatureEngineer
{
    public async Task<FeatureVector> ExtractFeaturesAsync(RequestContext context)
    {
        var features = new Dictionary<string, double>();
        
        // Request-level features
        features.AddRange(ExtractRequestFeatures(context.Request));
        
        // IP-level features
        features.AddRange(await ExtractIPFeaturesAsync(context.ClientIP));
        
        // User-level features
        features.AddRange(await ExtractUserFeaturesAsync(context.UserId));
        
        // Temporal features
        features.AddRange(ExtractTemporalFeatures(context.Timestamp));
        
        // Interaction features
        features.AddRange(CreateInteractionFeatures(features));
        
        return new FeatureVector
        {
            Features = features,
            Timestamp = context.Timestamp,
            Version = CurrentFeatureVersion
        };
    }
    
    private Dictionary<string, double> ExtractRequestFeatures(HttpRequest request)
    {
        return new Dictionary<string, double>
        {
            ["ContentLength"] = NormalizeContentLength(request.ContentLength ?? 0),
            ["UrlLength"] = NormalizeUrlLength(request.Path.Value?.Length ?? 0),
            ["ParameterCount"] = NormalizeParameterCount(request.Query.Count),
            ["HeaderCount"] = NormalizeHeaderCount(request.Headers.Count),
            ["UserAgentEntropy"] = CalculateUserAgentEntropy(request.Headers["User-Agent"]),
            ["HasReferer"] = request.Headers.ContainsKey("Referer") ? 1 : 0,
            ["IsAjax"] = IsAjaxRequest(request) ? 1 : 0,
            ["HttpsUsed"] = request.IsHttps ? 1 : 0
        };
    }
    
    private async Task<Dictionary<string, double>> ExtractIPFeaturesAsync(string ipAddress)
    {
        var ipRecord = await _ipRepository.GetByIPAddressAsync(ipAddress);
        
        if (ipRecord == null)
        {
            return new Dictionary<string, double>
            {
                ["IsNewIP"] = 1,
                ["ThreatScore"] = 0,
                ["TrustScore"] = 50,
                ["RequestCount"] = 0,
                ["DaysSinceFirstSeen"] = 0
            };
        }
        
        return new Dictionary<string, double>
        {
            ["IsNewIP"] = 0,
            ["ThreatScore"] = ipRecord.ThreatScore / 100.0,
            ["TrustScore"] = ipRecord.TrustScore / 100.0,
            ["RequestCount"] = NormalizeRequestCount(ipRecord.RequestCount),
            ["DaysSinceFirstSeen"] = NormalizeDaysSince(ipRecord.FirstSeenAt),
            ["ThreatIncidents"] = NormalizeThreatIncidents(ipRecord.ThreatIncidents),
            ["IsBlocked"] = ipRecord.IsBlocked ? 1 : 0
        };
    }
}
```

## Composite Scoring Algorithms

### Weighted Composite Scoring
```csharp
public class CompositeThreatScorer
{
    private readonly ScoringConfiguration _config;
    
    public CompositeThreatScore CalculateCompositeScore(ThreatScoringInputs inputs)
    {
        var componentScores = new Dictionary<string, ComponentScore>
        {
            ["IPReputation"] = ScoreIPReputation(inputs.IPReputationScore),
            ["PatternMatching"] = ScorePatternMatches(inputs.PatternMatches),
            ["BehavioralAnalysis"] = ScoreBehavioralAnalysis(inputs.BehavioralScore),
            ["ParameterJacking"] = ScoreParameterJacking(inputs.ParameterJackingScore),
            ["GeographicRisk"] = ScoreGeographicRisk(inputs.GeographicScore),
            ["MachineLearning"] = ScoreMLPrediction(inputs.MLScore)
        };
        
        var overallScore = CalculateWeightedScore(componentScores);
        var confidence = CalculateOverallConfidence(componentScores);
        var threatLevel = DetermineThreatLevel(overallScore);
        
        return new CompositeThreatScore
        {
            OverallScore = overallScore,
            ComponentScores = componentScores,
            Confidence = confidence,
            ThreatLevel = threatLevel,
            RecommendedAction = DetermineAction(overallScore, confidence),
            ScoringVersion = _config.Version
        };
    }
    
    private double CalculateWeightedScore(Dictionary<string, ComponentScore> scores)
    {
        var weights = _config.ComponentWeights;
        var normalizedWeights = NormalizeWeights(weights, scores.Keys);
        
        var weightedSum = scores.Sum(kvp =>
        {
            var weight = normalizedWeights.GetValueOrDefault(kvp.Key, 0);
            var score = kvp.Value.Score;
            var confidence = kvp.Value.Confidence;
            
            return weight * score * confidence;
        });
        
        var totalConfidenceWeight = scores.Sum(kvp =>
        {
            var weight = normalizedWeights.GetValueOrDefault(kvp.Key, 0);
            var confidence = kvp.Value.Confidence;
            
            return weight * confidence;
        });
        
        return totalConfidenceWeight > 0 ? weightedSum / totalConfidenceWeight : 0;
    }
    
    private Dictionary<string, double> NormalizeWeights(
        Dictionary<string, double> weights, 
        IEnumerable<string> availableComponents)
    {
        var availableWeights = weights
            .Where(kvp => availableComponents.Contains(kvp.Key))
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            
        var totalWeight = availableWeights.Values.Sum();
        
        if (totalWeight == 0) return availableWeights;
        
        return availableWeights.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value / totalWeight);
    }
}
```

### Adaptive Scoring Weights
```csharp
public class AdaptiveScoringWeightCalculator
{
    public ScoringWeights CalculateAdaptiveWeights(ScoringContext context)
    {
        var baseWeights = GetBaseWeights();
        var adaptiveWeights = new Dictionary<string, double>(baseWeights);
        
        // Adjust weights based on context
        AdjustForRequestType(adaptiveWeights, context.RequestType);
        AdjustForTimeOfDay(adaptiveWeights, context.Timestamp);
        AdjustForUserProfile(adaptiveWeights, context.UserProfile);
        AdjustForThreatIntelligence(adaptiveWeights, context.CurrentThreats);
        
        // Normalize weights to sum to 1.0
        NormalizeWeights(adaptiveWeights);
        
        return new ScoringWeights(adaptiveWeights);
    }
    
    private void AdjustForRequestType(Dictionary<string, double> weights, RequestType requestType)
    {
        switch (requestType)
        {
            case RequestType.API:
                weights["PatternMatching"] *= 1.3;  // APIs are more susceptible to injection
                weights["ParameterJacking"] *= 1.2; // Parameter attacks common in APIs
                break;
                
            case RequestType.AdminPanel:
                weights["IPReputation"] *= 1.4;     // Admin access should be from trusted IPs
                weights["GeographicRisk"] *= 1.3;   // Geographic restrictions more important
                break;
                
            case RequestType.UserContent:
                weights["PatternMatching"] *= 1.2;  // XSS and content injection risks
                weights["BehavioralAnalysis"] *= 1.1; // Behavioral patterns important
                break;
                
            case RequestType.FileUpload:
                weights["PatternMatching"] *= 1.5;  // File upload attacks
                weights["MachineLearning"] *= 1.2;  // ML good for file analysis
                break;
        }
    }
    
    private void AdjustForTimeOfDay(Dictionary<string, double> weights, DateTime timestamp)
    {
        var hour = timestamp.Hour;
        
        // During off-hours, increase suspicion
        if (hour < 6 || hour > 22)
        {
            weights["BehavioralAnalysis"] *= 1.2;
            weights["GeographicRisk"] *= 1.1;
        }
        
        // During business hours, trust established patterns more
        if (hour >= 9 && hour <= 17)
        {
            weights["IPReputation"] *= 1.1;
            weights["BehavioralAnalysis"] *= 0.9;
        }
    }
}
```

## Real-Time Scoring Optimization

### Caching Strategies
```csharp
public class ScoringCacheManager
{
    private readonly IMemoryCache _memoryCache;
    private readonly IDistributedCache _distributedCache;
    
    public async Task<CachedScore?> GetCachedScoreAsync(string key, ScoringContext context)
    {
        // Check memory cache first (fastest)
        if (_memoryCache.TryGetValue(key, out CachedScore? memoryScore))
        {
            if (IsScoreValid(memoryScore, context))
                return memoryScore;
        }
        
        // Check distributed cache
        var distributedScore = await GetFromDistributedCacheAsync(key);
        if (distributedScore != null && IsScoreValid(distributedScore, context))
        {
            // Populate memory cache
            _memoryCache.Set(key, distributedScore, TimeSpan.FromMinutes(5));
            return distributedScore;
        }
        
        return null;
    }
    
    public async Task CacheScoreAsync(string key, CompositeThreatScore score, ScoringContext context)
    {
        var cachedScore = new CachedScore
        {
            Score = score,
            CachedAt = DateTime.UtcNow,
            Context = context,
            ExpiresAt = CalculateExpirationTime(score, context)
        };
        
        // Cache in memory (5 minutes)
        _memoryCache.Set(key, cachedScore, TimeSpan.FromMinutes(5));
        
        // Cache distributed (longer duration for stable scores)
        if (score.Confidence > 0.8)
        {
            await _distributedCache.SetAsync(key, 
                JsonSerializer.SerializeToUtf8Bytes(cachedScore),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
                });
        }
    }
    
    private bool IsScoreValid(CachedScore cachedScore, ScoringContext currentContext)
    {
        // Check expiration
        if (cachedScore.ExpiresAt < DateTime.UtcNow)
            return false;
            
        // Check context compatibility
        if (!IsContextCompatible(cachedScore.Context, currentContext))
            return false;
            
        // Check if any critical components have changed
        return !HasCriticalChanges(cachedScore, currentContext);
    }
}
```

### Parallel Scoring Execution
```csharp
public class ParallelScoringEngine
{
    private readonly SemaphoreSlim _concurrencySemaphore;
    
    public async Task<CompositeThreatScore> ScoreAsync(ScoringInputs inputs)
    {
        await _concurrencySemaphore.WaitAsync();
        
        try
        {
            var scoringTasks = new List<Task<ComponentScore>>();
            
            // Execute all scoring components in parallel
            if (inputs.HasIPData)
                scoringTasks.Add(ScoreIPReputationAsync(inputs.IPData));
                
            if (inputs.HasPatternData)
                scoringTasks.Add(ScorePatternMatchesAsync(inputs.PatternData));
                
            if (inputs.HasBehavioralData)
                scoringTasks.Add(ScoreBehavioralAsync(inputs.BehavioralData));
                
            if (inputs.HasParameterData)
                scoringTasks.Add(ScoreParameterJackingAsync(inputs.ParameterData));
                
            if (inputs.HasGeographicData)
                scoringTasks.Add(ScoreGeographicAsync(inputs.GeographicData));
                
            if (inputs.HasMLFeatures && _mlEnabled)
                scoringTasks.Add(ScoreMLAsync(inputs.MLFeatures));
                
            // Wait for all scoring to complete with timeout
            var timeout = TimeSpan.FromMilliseconds(1000); // 1 second max
            var completedScores = await Task.WhenAll(scoringTasks).WaitAsync(timeout);
            
            // Combine scores
            return CombineScores(completedScores.Where(s => s != null));
        }
        finally
        {
            _concurrencySemaphore.Release();
        }
    }
    
    private async Task<ComponentScore> ScoreIPReputationAsync(IPData ipData)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var score = await _ipScorer.ScoreAsync(ipData);
            stopwatch.Stop();
            
            RecordScoringPerformance("IPReputation", stopwatch.ElapsedMilliseconds);
            
            return new ComponentScore
            {
                Score = score.OverallScore,
                Confidence = score.Confidence,
                ExecutionTime = stopwatch.ElapsedMilliseconds,
                ComponentName = "IPReputation"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "IP reputation scoring failed");
            return ComponentScore.Failed("IPReputation");
        }
    }
}
```

### Performance Monitoring
```csharp
public class ScoringPerformanceMonitor
{
    private readonly IMetricsLogger _metrics;
    
    public void RecordScoringPerformance(string component, long executionTimeMs, double score)
    {
        _metrics.Counter("scoring_operations_total")
            .WithTag("component", component)
            .Increment();
            
        _metrics.Histogram("scoring_execution_time_ms")
            .WithTag("component", component)
            .Observe(executionTimeMs);
            
        _metrics.Histogram("scoring_values")
            .WithTag("component", component)
            .Observe(score);
            
        // Alert on slow scoring
        if (executionTimeMs > GetSlowThreshold(component))
        {
            _metrics.Counter("scoring_slow_operations_total")
                .WithTag("component", component)
                .Increment();
        }
        
        // Alert on extreme scores
        if (score > 90 || score < 5)
        {
            _metrics.Counter("scoring_extreme_values_total")
                .WithTag("component", component)
                .WithTag("score_range", GetScoreRange(score))
                .Increment();
        }
    }
    
    public ScoringPerformanceReport GeneratePerformanceReport(TimeSpan period)
    {
        var endTime = DateTime.UtcNow;
        var startTime = endTime.Subtract(period);
        
        return new ScoringPerformanceReport
        {
            Period = period,
            ComponentPerformance = GetComponentPerformance(startTime, endTime),
            OverallStatistics = GetOverallStatistics(startTime, endTime),
            PerformanceTrends = GetPerformanceTrends(startTime, endTime),
            Recommendations = GeneratePerformanceRecommendations()
        };
    }
}
```

## Scoring Calibration

### Score Distribution Analysis
```csharp
public class ScoreCalibrationAnalyzer
{
    public CalibrationReport AnalyzeScoreDistribution(List<ScoredRequest> historicalScores)
    {
        var scores = historicalScores.Select(r => r.OverallScore).ToList();
        
        var distribution = new ScoreDistribution
        {
            Mean = scores.Average(),
            Median = CalculateMedian(scores),
            StandardDeviation = CalculateStandardDeviation(scores),
            Percentiles = CalculatePercentiles(scores),
            Skewness = CalculateSkewness(scores),
            Kurtosis = CalculateKurtosis(scores)
        };
        
        var calibrationIssues = DetectCalibrationIssues(distribution);
        var recommendations = GenerateCalibrationRecommendations(calibrationIssues);
        
        return new CalibrationReport
        {
            Distribution = distribution,
            CalibrationIssues = calibrationIssues,
            Recommendations = recommendations,
            SampleSize = scores.Count,
            AnalysisDate = DateTime.UtcNow
        };
    }
    
    private List<CalibrationIssue> DetectCalibrationIssues(ScoreDistribution distribution)
    {
        var issues = new List<CalibrationIssue>();
        
        // Check for score compression (too many scores in narrow range)
        if (distribution.StandardDeviation < 15)
        {
            issues.Add(new CalibrationIssue
            {
                Type = CalibrationIssueType.ScoreCompression,
                Severity = CalibrationSeverity.Medium,
                Description = "Score distribution is too compressed, indicating poor discrimination",
                RecommendedAction = "Adjust scoring weights to increase variance"
            });
        }
        
        // Check for extreme skewness
        if (Math.Abs(distribution.Skewness) > 1.5)
        {
            issues.Add(new CalibrationIssue
            {
                Type = CalibrationIssueType.ExtremeSkewness,
                Severity = CalibrationSeverity.High,
                Description = $"Score distribution is heavily skewed ({distribution.Skewness:F2})",
                RecommendedAction = "Rebalance scoring algorithm weights"
            });
        }
        
        // Check for bimodal distribution
        if (DetectBimodalDistribution(distribution))
        {
            issues.Add(new CalibrationIssue
            {
                Type = CalibrationIssueType.BimodalDistribution,
                Severity = CalibrationSeverity.Medium,
                Description = "Score distribution appears bimodal",
                RecommendedAction = "Review scoring logic for conflicting algorithms"
            });
        }
        
        return issues;
    }
}
```

### Threshold Optimization
```csharp
public class ThresholdOptimizer
{
    public OptimalThresholds OptimizeThresholds(List<LabeledScoredRequest> labeledData)
    {
        var scores = labeledData.Select(r => r.Score).ToList();
        var labels = labeledData.Select(r => r.IsThreat).ToList();
        
        var thresholds = GenerateThresholdCandidates(scores);
        var bestThresholds = new Dictionary<SecurityAction, double>();
        
        foreach (var action in Enum.GetValues<SecurityAction>())
        {
            var bestThreshold = FindOptimalThreshold(scores, labels, action);
            bestThresholds[action] = bestThreshold;
        }
        
        return new OptimalThresholds
        {
            ActionThresholds = bestThresholds,
            Performance = EvaluateThresholdPerformance(labeledData, bestThresholds),
            OptimizationCriteria = OptimizationCriteria.F1Score,
            SampleSize = labeledData.Count
        };
    }
    
    private double FindOptimalThreshold(List<double> scores, List<bool> labels, SecurityAction action)
    {
        var candidates = GenerateThresholdCandidates(scores);
        var bestThreshold = 50.0;
        var bestF1Score = 0.0;
        
        foreach (var threshold in candidates)
        {
            var predictions = scores.Select(s => ShouldTakeAction(s, threshold, action)).ToList();
            var metrics = CalculateMetrics(labels, predictions);
            
            if (metrics.F1Score > bestF1Score)
            {
                bestF1Score = metrics.F1Score;
                bestThreshold = threshold;
            }
        }
        
        return bestThreshold;
    }
    
    private PerformanceMetrics CalculateMetrics(List<bool> actualLabels, List<bool> predictions)
    {
        var tp = actualLabels.Zip(predictions, (a, p) => a && p).Count(x => x);
        var fp = actualLabels.Zip(predictions, (a, p) => !a && p).Count(x => x);
        var tn = actualLabels.Zip(predictions, (a, p) => !a && !p).Count(x => x);
        var fn = actualLabels.Zip(predictions, (a, p) => a && !p).Count(x => x);
        
        var precision = tp + fp > 0 ? (double)tp / (tp + fp) : 0;
        var recall = tp + fn > 0 ? (double)tp / (tp + fn) : 0;
        var f1Score = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
        var accuracy = (double)(tp + tn) / (tp + fp + tn + fn);
        
        return new PerformanceMetrics
        {
            Precision = precision,
            Recall = recall,
            F1Score = f1Score,
            Accuracy = accuracy,
            TruePositives = tp,
            FalsePositives = fp,
            TrueNegatives = tn,
            FalseNegatives = fn
        };
    }
}
```

## Algorithm Performance

### Performance Benchmarking
```csharp
public class ScoringBenchmark
{
    public async Task<BenchmarkResults> RunBenchmarkAsync(BenchmarkConfiguration config)
    {
        var results = new List<BenchmarkResult>();
        
        // Warm up
        await WarmUpAsync(config.WarmUpRequests);
        
        // Run benchmark iterations
        for (int i = 0; i < config.Iterations; i++)
        {
            var iteration = await RunBenchmarkIterationAsync(config);
            results.Add(iteration);
        }
        
        return new BenchmarkResults
        {
            Configuration = config,
            Results = results,
            Summary = CalculateBenchmarkSummary(results),
            PerformanceProfile = GeneratePerformanceProfile(results),
            Recommendations = GeneratePerformanceRecommendations(results)
        };
    }
    
    private async Task<BenchmarkResult> RunBenchmarkIterationAsync(BenchmarkConfiguration config)
    {
        var requests = GenerateBenchmarkRequests(config.RequestCount);
        var stopwatch = Stopwatch.StartNew();
        var scores = new List<CompositeThreatScore>();
        var memoryBefore = GC.GetTotalMemory(false);
        
        var tasks = requests.Select(async request =>
        {
            var scoringInput = CreateScoringInput(request);
            return await _scoringEngine.ScoreAsync(scoringInput);
        });
        
        scores.AddRange(await Task.WhenAll(tasks));
        
        stopwatch.Stop();
        var memoryAfter = GC.GetTotalMemory(false);
        
        return new BenchmarkResult
        {
            RequestCount = config.RequestCount,
            TotalTime = stopwatch.Elapsed,
            AverageTime = TimeSpan.FromMilliseconds(stopwatch.ElapsedMilliseconds / (double)requests.Count),
            ThroughputPerSecond = requests.Count / stopwatch.Elapsed.TotalSeconds,
            MemoryUsed = memoryAfter - memoryBefore,
            Scores = scores
        };
    }
}
```

### Performance Optimization Recommendations
```csharp
public class PerformanceOptimizer
{
    public OptimizationPlan GenerateOptimizationPlan(PerformanceProfile profile)
    {
        var optimizations = new List<PerformanceOptimization>();
        
        // Analyze bottlenecks
        if (profile.SlowComponents.Any())
        {
            optimizations.AddRange(OptimizeSlowComponents(profile.SlowComponents));
        }
        
        // Memory optimization
        if (profile.MemoryUsage > MemoryThresholds.High)
        {
            optimizations.AddRange(OptimizeMemoryUsage(profile));
        }
        
        // Caching optimization
        if (profile.CacheHitRatio < 0.8)
        {
            optimizations.AddRange(OptimizeCaching(profile));
        }
        
        // Parallelization optimization
        if (profile.ConcurrencyUtilization < 0.6)
        {
            optimizations.AddRange(OptimizeParallelization(profile));
        }
        
        return new OptimizationPlan
        {
            Optimizations = optimizations.OrderByDescending(o => o.ExpectedImpact).ToList(),
            EstimatedImprovement = CalculateEstimatedImprovement(optimizations),
            ImplementationComplexity = CalculateImplementationComplexity(optimizations)
        };
    }
    
    private List<PerformanceOptimization> OptimizeSlowComponents(List<ComponentPerformance> slowComponents)
    {
        var optimizations = new List<PerformanceOptimization>();
        
        foreach (var component in slowComponents)
        {
            switch (component.ComponentName)
            {
                case "IPReputation":
                    optimizations.Add(new PerformanceOptimization
                    {
                        Component = "IPReputation",
                        Type = OptimizationType.Caching,
                        Description = "Implement aggressive IP reputation caching",
                        ExpectedImpact = EstimateImpact(component.AverageTime, 0.7), // 70% improvement
                        ImplementationEffort = ImplementationEffort.Low
                    });
                    break;
                    
                case "PatternMatching":
                    optimizations.Add(new PerformanceOptimization
                    {
                        Component = "PatternMatching",
                        Type = OptimizationType.Algorithm,
                        Description = "Optimize regex compilation and use compiled patterns",
                        ExpectedImpact = EstimateImpact(component.AverageTime, 0.5), // 50% improvement
                        ImplementationEffort = ImplementationEffort.Medium
                    });
                    break;
                    
                case "MachineLearning":
                    optimizations.Add(new PerformanceOptimization
                    {
                        Component = "MachineLearning",
                        Type = OptimizationType.Infrastructure,
                        Description = "Use GPU acceleration for ML inference",
                        ExpectedImpact = EstimateImpact(component.AverageTime, 0.8), // 80% improvement
                        ImplementationEffort = ImplementationEffort.High
                    });
                    break;
            }
        }
        
        return optimizations;
    }
}
```

## Validation and Testing

### Algorithm Validation Framework
```csharp
public class ScoringAlgorithmValidator
{
    public async Task<ValidationReport> ValidateAlgorithmAsync(ValidationConfiguration config)
    {
        var testCases = await LoadTestCasesAsync(config.TestDataPath);
        var validationResults = new List<ValidationResult>();
        
        foreach (var testCase in testCases)
        {
            var result = await ValidateTestCaseAsync(testCase);
            validationResults.Add(result);
        }
        
        var overallMetrics = CalculateOverallMetrics(validationResults);
        var componentMetrics = CalculateComponentMetrics(validationResults);
        
        return new ValidationReport
        {
            OverallMetrics = overallMetrics,
            ComponentMetrics = componentMetrics,
            ValidationResults = validationResults,
            TestCaseCount = testCases.Count,
            PassRate = CalculatePassRate(validationResults),
            Issues = IdentifyValidationIssues(validationResults)
        };
    }
    
    private async Task<ValidationResult> ValidateTestCaseAsync(ScoringTestCase testCase)
    {
        var scoringInput = CreateScoringInput(testCase.RequestData);
        var actualScore = await _scoringEngine.ScoreAsync(scoringInput);
        
        var expectedRange = testCase.ExpectedScoreRange;
        var isWithinRange = actualScore.OverallScore >= expectedRange.Min && 
                           actualScore.OverallScore <= expectedRange.Max;
        
        var expectedAction = testCase.ExpectedAction;
        var actualAction = DetermineAction(actualScore.OverallScore);
        var isCorrectAction = actualAction == expectedAction;
        
        return new ValidationResult
        {
            TestCase = testCase,
            ActualScore = actualScore,
            IsScoreValid = isWithinRange,
            IsActionValid = isCorrectAction,
            ScoreDeviation = CalculateScoreDeviation(actualScore.OverallScore, expectedRange),
            ComponentValidation = ValidateComponents(actualScore, testCase)
        };
    }
}
```

### A/B Testing Framework
```csharp
public class ScoringABTestFramework
{
    public async Task<ABTestResult> RunABTestAsync(ABTestConfiguration config)
    {
        var controlGroup = await RunScoringExperiment(config.ControlAlgorithm, config.TestData);
        var treatmentGroup = await RunScoringExperiment(config.TreatmentAlgorithm, config.TestData);
        
        var comparison = CompareResults(controlGroup, treatmentGroup);
        var statisticalSignificance = CalculateStatisticalSignificance(controlGroup, treatmentGroup);
        
        return new ABTestResult
        {
            ControlResults = controlGroup,
            TreatmentResults = treatmentGroup,
            Comparison = comparison,
            StatisticalSignificance = statisticalSignificance,
            Recommendation = GenerateRecommendation(comparison, statisticalSignificance)
        };
    }
    
    private async Task<ExperimentResults> RunScoringExperiment(
        IScoringAlgorithm algorithm, 
        List<TestRequest> testData)
    {
        var results = new List<ScoringResult>();
        var performanceMetrics = new PerformanceMetrics();
        
        var stopwatch = Stopwatch.StartNew();
        
        foreach (var testRequest in testData)
        {
            var requestStopwatch = Stopwatch.StartNew();
            var score = await algorithm.ScoreAsync(testRequest);
            requestStopwatch.Stop();
            
            results.Add(new ScoringResult
            {
                Request = testRequest,
                Score = score,
                ExecutionTime = requestStopwatch.ElapsedMilliseconds
            });
        }
        
        stopwatch.Stop();
        
        return new ExperimentResults
        {
            Algorithm = algorithm.GetType().Name,
            Results = results,
            OverallExecutionTime = stopwatch.Elapsed,
            AverageExecutionTime = results.Average(r => r.ExecutionTime),
            ThroughputPerSecond = results.Count / stopwatch.Elapsed.TotalSeconds,
            ScoreDistribution = CalculateScoreDistribution(results.Select(r => r.Score.OverallScore))
        };
    }
}
```

---

This Scoring Algorithms specification provides comprehensive coverage of all scoring methodologies used in the SecurityFramework, including mathematical formulations, implementation details, optimization techniques, and validation frameworks. The algorithms are designed for high-performance real-time threat assessment while maintaining accuracy and adaptability.