# Machine Learning Integration Guide

This document outlines the optional ML.NET integration for the Security Framework, providing advanced threat detection, predictive analytics, and adaptive security responses.

## Table of Contents

1. [Overview](#overview)
2. [ML.NET Integration Architecture](#mlnet-integration-architecture)
3. [Threat Prediction Models](#threat-prediction-models)
4. [Anomaly Detection](#anomaly-detection)
5. [Behavioral Analysis](#behavioral-analysis)
6. [Model Training and Updates](#model-training-and-updates)
7. [Real-Time Scoring](#real-time-scoring)
8. [Model Management](#model-management)
9. [Configuration](#configuration)
10. [Performance Considerations](#performance-considerations)
11. [Monitoring and Metrics](#monitoring-and-metrics)
12. [Examples and Use Cases](#examples-and-use-cases)

## Overview

The ML.NET integration provides advanced machine learning capabilities that enhance the Security Framework's threat detection and scoring algorithms. This is an **optional component** that can be enabled when advanced predictive capabilities are required.

### Key Features

- **Threat Prediction**: Predict future security incidents based on historical patterns
- **Anomaly Detection**: Identify unusual behavior patterns in real-time
- **Adaptive Scoring**: ML-enhanced threat scoring that improves over time
- **Behavioral Profiling**: Build user and IP behavior profiles
- **Pattern Recognition**: Automatically discover new threat patterns
- **Risk Assessment**: Advanced risk scoring using ensemble models

### ML Models Included

1. **Threat Classification Model**: Binary classification for threat/non-threat
2. **Anomaly Detection Model**: Unsupervised learning for outlier detection
3. **Risk Scoring Model**: Regression model for numerical risk scores
4. **Behavioral Model**: Time-series analysis for behavior patterns
5. **Pattern Discovery Model**: Clustering for new threat pattern identification

## ML.NET Integration Architecture

### Component Structure

```
SecurityFramework.ML/
├── Models/                        # ML model definitions
│   ├── ThreatClassificationModel.cs
│   ├── AnomalyDetectionModel.cs
│   ├── RiskScoringModel.cs
│   └── BehaviorAnalysisModel.cs
├── Services/                      # ML services
│   ├── IMLPredictionService.cs
│   ├── MLPredictionService.cs
│   ├── IModelTrainingService.cs
│   └── ModelTrainingService.cs
├── Training/                      # Training pipelines
│   ├── ThreatClassificationTrainer.cs
│   └── AnomalyDetectionTrainer.cs
├── Data/                         # ML data structures
│   ├── ThreatPredictionData.cs
│   └── ModelFeatures.cs
└── Extensions/                   # DI extensions
    └── MLServiceExtensions.cs
```

### Core ML Service Interface

```csharp
public interface IMLPredictionService
{
    /// <summary>
    /// Predicts threat probability for an IP address using ML models
    /// </summary>
    Task<ThreatPrediction> PredictThreatAsync(string ipAddress, ThreatContext context);
    
    /// <summary>
    /// Detects anomalies in request patterns
    /// </summary>
    Task<AnomalyResult> DetectAnomalyAsync(RequestPattern pattern);
    
    /// <summary>
    /// Calculates ML-enhanced risk score
    /// </summary>
    Task<double> CalculateRiskScoreAsync(SecurityMetrics metrics);
    
    /// <summary>
    /// Analyzes behavioral patterns for users/IPs
    /// </summary>
    Task<BehaviorProfile> AnalyzeBehaviorAsync(string identifier, List<SecurityEvent> events);
    
    /// <summary>
    /// Discovers new threat patterns automatically
    /// </summary>
    Task<List<DiscoveredPattern>> DiscoverPatternsAsync(List<SecurityIncident> incidents);
}
```

## Threat Prediction Models

### Binary Classification Model

Predicts whether a request is likely to be malicious:

```csharp
public class ThreatClassificationModel
{
    public class ModelInput
    {
        [LoadColumn(0)]
        public string IPAddress { get; set; }
        
        [LoadColumn(1)]
        public float RequestFrequency { get; set; }
        
        [LoadColumn(2)]
        public float GeographicRisk { get; set; }
        
        [LoadColumn(3)]
        public float TimeOfDayRisk { get; set; }
        
        [LoadColumn(4)]
        public float HistoricalThreatScore { get; set; }
        
        [LoadColumn(5)]
        public float UserAgentRisk { get; set; }
        
        [LoadColumn(6)]
        public float PayloadSuspiciousness { get; set; }
        
        [LoadColumn(7)]
        public bool IsThreat { get; set; }
    }
    
    public class ModelOutput
    {
        [ColumnName("PredictedLabel")]
        public bool IsThreat { get; set; }
        
        [ColumnName("Probability")]
        public float Probability { get; set; }
        
        [ColumnName("Score")]
        public float Score { get; set; }
    }
}

public class ThreatClassificationTrainer
{
    private readonly MLContext _mlContext;
    
    public ThreatClassificationTrainer()
    {
        _mlContext = new MLContext(seed: 42);
    }
    
    public ITransformer TrainModel(IDataView trainingData)
    {
        var pipeline = _mlContext.Transforms.Text.FeaturizeText("IPAddressFeaturized", nameof(ThreatClassificationModel.ModelInput.IPAddress))
            .Append(_mlContext.Transforms.Concatenate("Features",
                "IPAddressFeaturized",
                nameof(ThreatClassificationModel.ModelInput.RequestFrequency),
                nameof(ThreatClassificationModel.ModelInput.GeographicRisk),
                nameof(ThreatClassificationModel.ModelInput.TimeOfDayRisk),
                nameof(ThreatClassificationModel.ModelInput.HistoricalThreatScore),
                nameof(ThreatClassificationModel.ModelInput.UserAgentRisk),
                nameof(ThreatClassificationModel.ModelInput.PayloadSuspiciousness)))
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(
                labelColumnName: nameof(ThreatClassificationModel.ModelInput.IsThreat),
                featureColumnName: "Features"));
        
        var model = pipeline.Fit(trainingData);
        
        return model;
    }
}
```

### Risk Scoring Model

Provides numerical risk scores using regression:

```csharp
public class RiskScoringModel
{
    public class ModelInput
    {
        [LoadColumn(0)]
        public float ThreatIndicators { get; set; }
        
        [LoadColumn(1)]
        public float BehaviorDeviation { get; set; }
        
        [LoadColumn(2)]
        public float ContextualRisk { get; set; }
        
        [LoadColumn(3)]
        public float HistoricalPattern { get; set; }
        
        [LoadColumn(4)]
        public float RiskScore { get; set; }
    }
    
    public class ModelOutput
    {
        [ColumnName("Score")]
        public float PredictedRiskScore { get; set; }
    }
}

public class RiskScoringTrainer
{
    private readonly MLContext _mlContext;
    
    public RiskScoringTrainer()
    {
        _mlContext = new MLContext(seed: 42);
    }
    
    public ITransformer TrainModel(IDataView trainingData)
    {
        var pipeline = _mlContext.Transforms.Concatenate("Features",
                nameof(RiskScoringModel.ModelInput.ThreatIndicators),
                nameof(RiskScoringModel.ModelInput.BehaviorDeviation),
                nameof(RiskScoringModel.ModelInput.ContextualRisk),
                nameof(RiskScoringModel.ModelInput.HistoricalPattern))
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.Regression.Trainers.FastTree(
                labelColumnName: nameof(RiskScoringModel.ModelInput.RiskScore),
                featureColumnName: "Features"));
        
        return pipeline.Fit(trainingData);
    }
}
```

## Anomaly Detection

### Unsupervised Anomaly Detection

Identifies unusual patterns without labeled data:

```csharp
public class AnomalyDetectionModel
{
    public class ModelInput
    {
        [LoadColumn(0)]
        public float RequestRate { get; set; }
        
        [LoadColumn(1)]
        public float SessionDuration { get; set; }
        
        [LoadColumn(2)]
        public float PayloadSize { get; set; }
        
        [LoadColumn(3)]
        public float ErrorRate { get; set; }
        
        [LoadColumn(4)]
        public float GeographicVariation { get; set; }
    }
    
    public class ModelOutput
    {
        [ColumnName("PredictedLabel")]
        public bool IsAnomaly { get; set; }
        
        [ColumnName("Score")]
        public float AnomalyScore { get; set; }
    }
}

public class AnomalyDetectionService
{
    private readonly PredictionEngine<AnomalyDetectionModel.ModelInput, AnomalyDetectionModel.ModelOutput> _predictionEngine;
    
    public AnomalyDetectionService(ITransformer model, MLContext mlContext)
    {
        _predictionEngine = mlContext.Model.CreatePredictionEngine<AnomalyDetectionModel.ModelInput, AnomalyDetectionModel.ModelOutput>(model);
    }
    
    public async Task<AnomalyResult> DetectAnomalyAsync(RequestPattern pattern)
    {
        var input = new AnomalyDetectionModel.ModelInput
        {
            RequestRate = pattern.RequestRate,
            SessionDuration = pattern.SessionDuration,
            PayloadSize = pattern.PayloadSize,
            ErrorRate = pattern.ErrorRate,
            GeographicVariation = pattern.GeographicVariation
        };
        
        var prediction = _predictionEngine.Predict(input);
        
        return new AnomalyResult
        {
            IsAnomaly = prediction.IsAnomaly,
            AnomalyScore = prediction.AnomalyScore,
            Confidence = CalculateConfidence(prediction.AnomalyScore),
            DetectedAt = DateTime.UtcNow,
            Pattern = pattern
        };
    }
    
    private double CalculateConfidence(float score)
    {
        // Convert anomaly score to confidence percentage
        return Math.Min(Math.Abs(score) * 100, 100);
    }
}
```

## Behavioral Analysis

### Time-Series Behavior Modeling

```csharp
public class BehaviorAnalysisModel
{
    public class ModelInput
    {
        [LoadColumn(0)]
        public float HourOfDay { get; set; }
        
        [LoadColumn(1)]
        public float DayOfWeek { get; set; }
        
        [LoadColumn(2)]
        public float RequestCount { get; set; }
        
        [LoadColumn(3)]
        public float SessionLength { get; set; }
        
        [LoadColumn(4)]
        public float ResourceAccess { get; set; }
        
        [LoadColumn(5)]
        public float BehaviorNormalcy { get; set; }
    }
    
    public class ModelOutput
    {
        [ColumnName("Score")]
        public float NormalcyScore { get; set; }
    }
}

public class BehaviorAnalysisService
{
    private readonly PredictionEngine<BehaviorAnalysisModel.ModelInput, BehaviorAnalysisModel.ModelOutput> _predictionEngine;
    private readonly IMemoryCache _behaviorCache;
    
    public async Task<BehaviorProfile> AnalyzeBehaviorAsync(string identifier, List<SecurityEvent> events)
    {
        var profile = await GetOrCreateBehaviorProfile(identifier);
        
        // Analyze recent behavior patterns
        var recentEvents = events.Where(e => e.Timestamp > DateTime.UtcNow.AddHours(-24)).ToList();
        var behaviorMetrics = ExtractBehaviorMetrics(recentEvents);
        
        // Predict normalcy using ML model
        var prediction = _predictionEngine.Predict(behaviorMetrics);
        
        // Update profile with new data
        profile.UpdateWith(behaviorMetrics, prediction.NormalcyScore);
        
        // Detect significant behavior changes
        var behaviorChange = DetectBehaviorChange(profile);
        
        return new BehaviorProfile
        {
            Identifier = identifier,
            NormalcyScore = prediction.NormalcyScore,
            BehaviorChange = behaviorChange,
            LastUpdated = DateTime.UtcNow,
            EventCount = events.Count,
            Patterns = ExtractPatterns(events)
        };
    }
    
    private BehaviorAnalysisModel.ModelInput ExtractBehaviorMetrics(List<SecurityEvent> events)
    {
        var now = DateTime.UtcNow;
        var avgRequestsPerHour = events.GroupBy(e => e.Timestamp.Hour).Average(g => g.Count());
        var avgSessionLength = events.Where(e => e.SessionId != null)
            .GroupBy(e => e.SessionId)
            .Average(g => (g.Max(e => e.Timestamp) - g.Min(e => e.Timestamp)).TotalMinutes);
        
        return new BehaviorAnalysisModel.ModelInput
        {
            HourOfDay = now.Hour,
            DayOfWeek = (float)now.DayOfWeek,
            RequestCount = avgRequestsPerHour,
            SessionLength = (float)avgSessionLength,
            ResourceAccess = events.Select(e => e.ResourcePath).Distinct().Count()
        };
    }
}
```

## Model Training and Updates

### Automated Model Retraining

```csharp
public class ModelTrainingService : IModelTrainingService
{
    private readonly MLContext _mlContext;
    private readonly ISecurityDataService _dataService;
    private readonly IModelStorage _modelStorage;
    private readonly ILogger<ModelTrainingService> _logger;
    
    public async Task<TrainingResult> TrainThreatClassificationModelAsync(DateTime fromDate, DateTime toDate)
    {
        try
        {
            // Fetch training data
            var trainingData = await _dataService.GetTrainingDataAsync(fromDate, toDate);
            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);
            
            // Split data for training and validation
            var splitData = _mlContext.Data.TrainTestSplit(dataView, testFraction: 0.2);
            
            // Train model
            var trainer = new ThreatClassificationTrainer();
            var model = trainer.TrainModel(splitData.TrainSet);
            
            // Evaluate model
            var predictions = model.Transform(splitData.TestSet);
            var metrics = _mlContext.BinaryClassification.Evaluate(predictions);
            
            // Save model if performance is acceptable
            if (metrics.Accuracy > 0.85 && metrics.F1Score > 0.80)
            {
                await _modelStorage.SaveModelAsync("ThreatClassification", model);
                
                return new TrainingResult
                {
                    Success = true,
                    ModelName = "ThreatClassification",
                    Accuracy = metrics.Accuracy,
                    F1Score = metrics.F1Score,
                    TrainingDataCount = trainingData.Count(),
                    TrainedAt = DateTime.UtcNow
                };
            }
            else
            {
                _logger.LogWarning("Model performance below threshold. Accuracy: {Accuracy}, F1: {F1Score}", 
                    metrics.Accuracy, metrics.F1Score);
                
                return new TrainingResult { Success = false, Reason = "Performance below threshold" };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error training threat classification model");
            return new TrainingResult { Success = false, Reason = ex.Message };
        }
    }
    
    public async Task<TrainingResult> TrainAnomalyDetectionModelAsync(DateTime fromDate, DateTime toDate)
    {
        try
        {
            var trainingData = await _dataService.GetAnomalyTrainingDataAsync(fromDate, toDate);
            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);
            
            // Use Random Cut Forest for anomaly detection
            var pipeline = _mlContext.AnomalyDetection.Trainers.RandomizedPca(
                featureColumnName: "Features",
                rank: 28,
                ensureZeroMean: false);
            
            var model = pipeline.Fit(dataView);
            
            // Evaluate on validation set
            var testData = await _dataService.GetAnomalyTestDataAsync(fromDate.AddDays(-30), fromDate);
            var testDataView = _mlContext.Data.LoadFromEnumerable(testData);
            var predictions = model.Transform(testDataView);
            
            // Calculate custom metrics for anomaly detection
            var metrics = EvaluateAnomalyModel(predictions);
            
            if (metrics.Precision > 0.75 && metrics.Recall > 0.70)
            {
                await _modelStorage.SaveModelAsync("AnomalyDetection", model);
                
                return new TrainingResult
                {
                    Success = true,
                    ModelName = "AnomalyDetection",
                    Accuracy = metrics.Precision,
                    F1Score = 2 * (metrics.Precision * metrics.Recall) / (metrics.Precision + metrics.Recall),
                    TrainingDataCount = trainingData.Count(),
                    TrainedAt = DateTime.UtcNow
                };
            }
            
            return new TrainingResult { Success = false, Reason = "Anomaly detection performance below threshold" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error training anomaly detection model");
            return new TrainingResult { Success = false, Reason = ex.Message };
        }
    }
}
```

### Scheduled Model Updates

```csharp
public class ModelUpdateService : BackgroundService
{
    private readonly IModelTrainingService _trainingService;
    private readonly IMLPredictionService _predictionService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ModelUpdateService> _logger;
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var updateInterval = _configuration.GetValue<TimeSpan>("ML:ModelUpdateInterval", TimeSpan.FromDays(7));
        
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PerformScheduledUpdate();
                await Task.Delay(updateInterval, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during scheduled model update");
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken); // Retry in 1 hour
            }
        }
    }
    
    private async Task PerformScheduledUpdate()
    {
        var endDate = DateTime.UtcNow;
        var startDate = endDate.AddDays(-30); // Use last 30 days of data
        
        // Train threat classification model
        var threatResult = await _trainingService.TrainThreatClassificationModelAsync(startDate, endDate);
        if (threatResult.Success)
        {
            _logger.LogInformation("Successfully updated threat classification model. Accuracy: {Accuracy}", 
                threatResult.Accuracy);
        }
        
        // Train anomaly detection model
        var anomalyResult = await _trainingService.TrainAnomalyDetectionModelAsync(startDate, endDate);
        if (anomalyResult.Success)
        {
            _logger.LogInformation("Successfully updated anomaly detection model. F1: {F1Score}", 
                anomalyResult.F1Score);
        }
        
        // Reload models in prediction service
        await _predictionService.ReloadModelsAsync();
    }
}
```

## Real-Time Scoring

### ML-Enhanced Security Service

```csharp
public class MLEnhancedSecurityService : ISecurityService
{
    private readonly ISecurityService _baseSecurityService;
    private readonly IMLPredictionService _mlPredictionService;
    private readonly ILogger<MLEnhancedSecurityService> _logger;
    
    public async Task<ThreatAssessment> AssessIPAsync(string ipAddress)
    {
        // Get base assessment
        var baseAssessment = await _baseSecurityService.AssessIPAsync(ipAddress);
        
        // Enhance with ML predictions
        var mlPrediction = await _mlPredictionService.PredictThreatAsync(ipAddress, 
            new ThreatContext { BaseScore = baseAssessment.ThreatScore });
        
        // Combine scores using weighted average
        var combinedScore = CombineScores(baseAssessment.ThreatScore, mlPrediction.ThreatProbability);
        
        return new ThreatAssessment
        {
            IPAddress = ipAddress,
            ThreatScore = combinedScore,
            ThreatLevel = DetermineThreatLevel(combinedScore),
            MLEnhanced = true,
            MLConfidence = mlPrediction.Confidence,
            BaseScore = baseAssessment.ThreatScore,
            MLScore = mlPrediction.ThreatProbability * 100,
            AssessedAt = DateTime.UtcNow,
            Flags = baseAssessment.Flags.Concat(mlPrediction.Flags).ToList()
        };
    }
    
    private double CombineScores(double baseScore, double mlProbability)
    {
        // Weighted combination: 60% ML prediction, 40% base score
        const double mlWeight = 0.6;
        const double baseWeight = 0.4;
        
        var mlScore = mlProbability * 100;
        return (mlScore * mlWeight) + (baseScore * baseWeight);
    }
}
```

### Real-Time Anomaly Detection

```csharp
public class RealTimeAnomalyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IMLPredictionService _mlService;
    private readonly ILogger<RealTimeAnomalyMiddleware> _logger;
    
    public async Task InvokeAsync(HttpContext context)
    {
        var requestPattern = await ExtractRequestPattern(context);
        
        // Perform real-time anomaly detection
        var anomalyResult = await _mlService.DetectAnomalyAsync(requestPattern);
        
        if (anomalyResult.IsAnomaly && anomalyResult.AnomalyScore > 0.8)
        {
            _logger.LogWarning("Anomalous request detected from {IPAddress}. Score: {Score}", 
                context.Connection.RemoteIpAddress, anomalyResult.AnomalyScore);
            
            // Add anomaly information to context
            context.Items["AnomalyDetected"] = true;
            context.Items["AnomalyScore"] = anomalyResult.AnomalyScore;
            
            // Optionally block highly anomalous requests
            if (anomalyResult.AnomalyScore > 0.95)
            {
                context.Response.StatusCode = 429; // Too Many Requests
                await context.Response.WriteAsync("Request pattern anomaly detected");
                return;
            }
        }
        
        await _next(context);
    }
    
    private async Task<RequestPattern> ExtractRequestPattern(HttpContext context)
    {
        // Extract features for anomaly detection
        return new RequestPattern
        {
            RequestRate = await CalculateRequestRate(context),
            PayloadSize = context.Request.ContentLength ?? 0,
            UserAgent = context.Request.Headers.UserAgent,
            Referer = context.Request.Headers.Referer,
            AcceptLanguages = context.Request.Headers.AcceptLanguage.Count,
            CustomHeaders = context.Request.Headers.Count(h => !CommonHeaders.Contains(h.Key))
        };
    }
}
```

## Model Management

### Model Storage and Versioning

```csharp
public interface IModelStorage
{
    Task SaveModelAsync(string modelName, ITransformer model);
    Task<ITransformer> LoadModelAsync(string modelName);
    Task<ModelMetadata> GetModelMetadataAsync(string modelName);
    Task<List<ModelVersion>> GetModelVersionsAsync(string modelName);
    Task PromoteModelAsync(string modelName, string version);
    Task DeleteModelAsync(string modelName, string version);
}

public class ModelStorage : IModelStorage
{
    private readonly IConfiguration _configuration;
    private readonly MLContext _mlContext;
    private readonly ILogger<ModelStorage> _logger;
    
    public async Task SaveModelAsync(string modelName, ITransformer model)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var version = $"v{timestamp}";
        var modelPath = GetModelPath(modelName, version);
        
        // Ensure directory exists
        Directory.CreateDirectory(Path.GetDirectoryName(modelPath));
        
        // Save model
        _mlContext.Model.Save(model, null, modelPath);
        
        // Save metadata
        var metadata = new ModelMetadata
        {
            Name = modelName,
            Version = version,
            SavedAt = DateTime.UtcNow,
            Path = modelPath,
            Size = new FileInfo(modelPath).Length
        };
        
        await SaveModelMetadataAsync(metadata);
        
        _logger.LogInformation("Model {ModelName} version {Version} saved to {Path}", 
            modelName, version, modelPath);
    }
    
    public async Task<ITransformer> LoadModelAsync(string modelName)
    {
        var metadata = await GetLatestModelMetadataAsync(modelName);
        if (metadata == null)
        {
            throw new InvalidOperationException($"No model found for {modelName}");
        }
        
        if (!File.Exists(metadata.Path))
        {
            throw new FileNotFoundException($"Model file not found: {metadata.Path}");
        }
        
        return _mlContext.Model.Load(metadata.Path, out _);
    }
    
    private string GetModelPath(string modelName, string version)
    {
        var modelsDirectory = _configuration.GetValue<string>("ML:ModelsDirectory", "models");
        return Path.Combine(modelsDirectory, modelName, $"{modelName}_{version}.zip");
    }
}
```

### Model A/B Testing

```csharp
public class ModelABTestingService
{
    private readonly IModelStorage _modelStorage;
    private readonly ILogger<ModelABTestingService> _logger;
    private readonly Dictionary<string, ModelPerformanceTracker> _performanceTrackers;
    
    public async Task<ThreatPrediction> PredictWithABTestAsync(string modelName, ThreatClassificationModel.ModelInput input)
    {
        // Determine which model version to use (A or B)
        var useModelB = ShouldUseModelB(modelName);
        var version = useModelB ? "B" : "A";
        
        var model = await _modelStorage.LoadModelAsync($"{modelName}_{version}");
        var predictionEngine = _mlContext.Model.CreatePredictionEngine<ThreatClassificationModel.ModelInput, ThreatClassificationModel.ModelOutput>(model);
        
        var prediction = predictionEngine.Predict(input);
        
        // Track performance for A/B testing
        var tracker = _performanceTrackers.GetOrAdd($"{modelName}_{version}", _ => new ModelPerformanceTracker());
        tracker.RecordPrediction(prediction);
        
        return new ThreatPrediction
        {
            IsThreat = prediction.IsThreat,
            Probability = prediction.Probability,
            ModelVersion = version,
            Timestamp = DateTime.UtcNow
        };
    }
    
    private bool ShouldUseModelB(string modelName)
    {
        // Simple traffic split: 10% to model B for testing
        var hash = modelName.GetHashCode();
        return Math.Abs(hash % 100) < 10;
    }
    
    public async Task<ABTestResults> GetABTestResultsAsync(string modelName)
    {
        var trackerA = _performanceTrackers.GetValueOrDefault($"{modelName}_A");
        var trackerB = _performanceTrackers.GetValueOrDefault($"{modelName}_B");
        
        if (trackerA == null || trackerB == null)
        {
            return new ABTestResults { HasEnoughData = false };
        }
        
        return new ABTestResults
        {
            HasEnoughData = true,
            ModelAAccuracy = trackerA.Accuracy,
            ModelBAccuracy = trackerB.Accuracy,
            ModelALatency = trackerA.AverageLatency,
            ModelBLatency = trackerB.AverageLatency,
            StatisticalSignificance = CalculateStatisticalSignificance(trackerA, trackerB)
        };
    }
}
```

## Configuration

### ML.NET Configuration Options

```csharp
public class MLOptions
{
    public bool Enabled { get; set; } = false;
    
    public string ModelsDirectory { get; set; } = "models";
    
    public ModelUpdateOptions ModelUpdate { get; set; } = new();
    
    public ThreatPredictionOptions ThreatPrediction { get; set; } = new();
    
    public AnomalyDetectionOptions AnomalyDetection { get; set; } = new();
    
    public BehaviorAnalysisOptions BehaviorAnalysis { get; set; } = new();
    
    public PerformanceOptions Performance { get; set; } = new();
}

public class ModelUpdateOptions
{
    public TimeSpan UpdateInterval { get; set; } = TimeSpan.FromDays(7);
    
    public int MinimumDataPoints { get; set; } = 1000;
    
    public double MinimumAccuracy { get; set; } = 0.85;
    
    public bool EnableAutoUpdate { get; set; } = true;
    
    public bool EnableABTesting { get; set; } = false;
}

public class ThreatPredictionOptions
{
    public bool Enabled { get; set; } = true;
    
    public double ModelWeight { get; set; } = 0.6;
    
    public double ConfidenceThreshold { get; set; } = 0.7;
    
    public TimeSpan PredictionCacheTime { get; set; } = TimeSpan.FromMinutes(5);
}

public class AnomalyDetectionOptions
{
    public bool Enabled { get; set; } = true;
    
    public double AnomalyThreshold { get; set; } = 0.8;
    
    public double BlockingThreshold { get; set; } = 0.95;
    
    public int WindowSizeMinutes { get; set; } = 60;
}
```

### Configuration Example

```json
{
  "ML": {
    "Enabled": true,
    "ModelsDirectory": "/app/models",
    "ModelUpdate": {
      "UpdateInterval": "7.00:00:00",
      "MinimumDataPoints": 5000,
      "MinimumAccuracy": 0.85,
      "EnableAutoUpdate": true,
      "EnableABTesting": true
    },
    "ThreatPrediction": {
      "Enabled": true,
      "ModelWeight": 0.6,
      "ConfidenceThreshold": 0.7,
      "PredictionCacheTime": "00:05:00"
    },
    "AnomalyDetection": {
      "Enabled": true,
      "AnomalyThreshold": 0.8,
      "BlockingThreshold": 0.95,
      "WindowSizeMinutes": 60
    },
    "BehaviorAnalysis": {
      "Enabled": true,
      "ProfileRetentionDays": 90,
      "MinimumEventsForProfile": 50
    },
    "Performance": {
      "MaxConcurrentPredictions": 100,
      "PredictionTimeoutMs": 1000,
      "EnableModelPreloading": true
    }
  }
}
```

## Performance Considerations

### Model Loading and Caching

```csharp
public class CachedMLPredictionService : IMLPredictionService
{
    private readonly ConcurrentDictionary<string, (ITransformer Model, DateTime LoadedAt)> _modelCache;
    private readonly SemaphoreSlim _loadingSemaphore;
    private readonly MLOptions _options;
    
    public async Task<ThreatPrediction> PredictThreatAsync(string ipAddress, ThreatContext context)
    {
        var model = await GetOrLoadModelAsync("ThreatClassification");
        
        // Use thread-safe prediction engine pool
        using var predictionEngine = GetPredictionEngine<ThreatClassificationModel.ModelInput, ThreatClassificationModel.ModelOutput>(model);
        
        var input = CreateModelInput(ipAddress, context);
        var prediction = predictionEngine.Predict(input);
        
        return new ThreatPrediction
        {
            IsThreat = prediction.IsThreat,
            Probability = prediction.Probability,
            Confidence = CalculateConfidence(prediction),
            PredictedAt = DateTime.UtcNow
        };
    }
    
    private async Task<ITransformer> GetOrLoadModelAsync(string modelName)
    {
        if (_modelCache.TryGetValue(modelName, out var cached))
        {
            // Check if model is still fresh
            if (DateTime.UtcNow - cached.LoadedAt < _options.Performance.ModelCacheTime)
            {
                return cached.Model;
            }
        }
        
        await _loadingSemaphore.WaitAsync();
        try
        {
            // Double-check pattern
            if (_modelCache.TryGetValue(modelName, out cached))
            {
                if (DateTime.UtcNow - cached.LoadedAt < _options.Performance.ModelCacheTime)
                {
                    return cached.Model;
                }
            }
            
            var model = await _modelStorage.LoadModelAsync(modelName);
            _modelCache[modelName] = (model, DateTime.UtcNow);
            
            return model;
        }
        finally
        {
            _loadingSemaphore.Release();
        }
    }
}
```

### Batch Prediction Optimization

```csharp
public class BatchMLPredictionService
{
    public async Task<List<ThreatPrediction>> PredictBatchAsync(List<(string IpAddress, ThreatContext Context)> inputs)
    {
        var model = await GetOrLoadModelAsync("ThreatClassification");
        
        // Create batch input
        var batchInput = inputs.Select(input => CreateModelInput(input.IpAddress, input.Context)).ToList();
        var dataView = _mlContext.Data.LoadFromEnumerable(batchInput);
        
        // Perform batch prediction
        var predictions = model.Transform(dataView);
        var predictionResults = _mlContext.Data.CreateEnumerable<ThreatClassificationModel.ModelOutput>(predictions, reuseRowObject: false).ToList();
        
        // Map results back to original inputs
        return inputs.Zip(predictionResults, (input, prediction) => new ThreatPrediction
        {
            IPAddress = input.IpAddress,
            IsThreat = prediction.IsThreat,
            Probability = prediction.Probability,
            PredictedAt = DateTime.UtcNow
        }).ToList();
    }
}
```

## Monitoring and Metrics

### ML Performance Metrics

```csharp
public class MLMetricsCollector
{
    private readonly IMetricsLogger _metricsLogger;
    private readonly Timer _metricsTimer;
    
    public void RecordPredictionLatency(string modelName, TimeSpan latency)
    {
        _metricsLogger.RecordValue($"ml.prediction.latency.{modelName}", latency.TotalMilliseconds);
    }
    
    public void RecordModelAccuracy(string modelName, double accuracy)
    {
        _metricsLogger.RecordValue($"ml.model.accuracy.{modelName}", accuracy);
    }
    
    public void RecordAnomalyDetection(bool isAnomaly, double score)
    {
        _metricsLogger.IncrementCounter($"ml.anomaly.detected", new Dictionary<string, object>
        {
            ["is_anomaly"] = isAnomaly,
            ["score_range"] = GetScoreRange(score)
        });
    }
    
    public void RecordModelLoad(string modelName, TimeSpan loadTime)
    {
        _metricsLogger.RecordValue($"ml.model.load_time.{modelName}", loadTime.TotalMilliseconds);
    }
    
    private void CollectPerformanceMetrics()
    {
        // Collect memory usage
        var memoryUsage = GC.GetTotalMemory(false);
        _metricsLogger.RecordValue("ml.memory.usage", memoryUsage);
        
        // Collect model cache statistics
        var cacheHitRatio = CalculateCacheHitRatio();
        _metricsLogger.RecordValue("ml.cache.hit_ratio", cacheHitRatio);
    }
}
```

### ML Dashboard Integration

```csharp
public class MLDashboardHub : Hub
{
    private readonly IMLMetricsService _metricsService;
    
    public async Task GetMLMetrics()
    {
        var metrics = await _metricsService.GetCurrentMetricsAsync();
        await Clients.Caller.SendAsync("MLMetricsUpdate", metrics);
    }
    
    public async Task GetModelPerformance(string modelName)
    {
        var performance = await _metricsService.GetModelPerformanceAsync(modelName);
        await Clients.Caller.SendAsync("ModelPerformanceUpdate", performance);
    }
    
    [Authorize(Roles = "Admin")]
    public async Task TriggerModelRetrain(string modelName)
    {
        await _metricsService.TriggerModelRetrainAsync(modelName);
        await Clients.All.SendAsync("ModelRetrainStarted", modelName);
    }
}
```

## Examples and Use Cases

### E-Commerce Fraud Detection

```csharp
public class ECommerceFraudMLService
{
    public async Task<FraudAssessment> AssessPurchaseAsync(PurchaseContext purchase)
    {
        // Extract ML features
        var features = new FraudDetectionModel.ModelInput
        {
            OrderValue = (float)purchase.OrderTotal,
            UserAgeInDays = (float)(DateTime.UtcNow - purchase.UserRegistrationDate).TotalDays,
            PaymentMethodRisk = GetPaymentMethodRisk(purchase.PaymentMethod),
            ShippingSpeedRisk = GetShippingSpeedRisk(purchase.ShippingMethod),
            GeographicRisk = await GetGeographicRiskAsync(purchase.IPAddress, purchase.ShippingAddress),
            TimeOfDayRisk = GetTimeOfDayRisk(DateTime.UtcNow),
            DeviceFingerprint = purchase.DeviceFingerprint.GetHashCode()
        };
        
        var prediction = await _mlService.PredictFraudAsync(features);
        
        return new FraudAssessment
        {
            IsFraudulent = prediction.IsFraud,
            FraudProbability = prediction.Probability,
            RiskFactors = ExtractRiskFactors(features, prediction),
            RecommendedAction = DetermineAction(prediction.Probability)
        };
    }
}
```

### API Abuse Detection

```csharp
public class APIAbuseMLDetector
{
    public async Task<AbuseDetectionResult> DetectAbuseAsync(APICallPattern pattern)
    {
        var features = new APIAbuseModel.ModelInput
        {
            RequestRate = pattern.RequestsPerMinute,
            EndpointDiversity = pattern.UniqueEndpoints,
            ErrorRate = pattern.ErrorRate,
            PayloadSizeVariation = pattern.PayloadSizeStdDev,
            UserAgentConsistency = pattern.UserAgentVariations,
            AuthenticationPattern = GetAuthPatternRisk(pattern.AuthMethods),
            TimePattern = GetTimePatternRisk(pattern.RequestTimes)
        };
        
        var prediction = await _mlService.PredictAbuseAsync(features);
        
        if (prediction.IsAbuse && prediction.Confidence > 0.85)
        {
            return new AbuseDetectionResult
            {
                IsAbuse = true,
                AbuseType = ClassifyAbuseType(prediction),
                Confidence = prediction.Confidence,
                RecommendedAction = AbuseAction.RateLimit,
                Evidence = GenerateEvidence(features, prediction)
            };
        }
        
        return new AbuseDetectionResult { IsAbuse = false };
    }
}
```

This comprehensive ML.NET integration guide provides a foundation for implementing advanced machine learning capabilities in the Security Framework, enabling predictive threat detection, anomaly identification, and adaptive security responses.