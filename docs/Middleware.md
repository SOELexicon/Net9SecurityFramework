# SecurityFramework Middleware

## Overview

The SecurityFramework integrates seamlessly into the ASP.NET Core middleware pipeline, providing comprehensive security analysis and threat detection for every HTTP request. This document covers the complete middleware architecture, configuration options, performance optimizations, and integration patterns.

## Table of Contents

1. [Middleware Architecture](#middleware-architecture)
2. [Core Security Middleware](#core-security-middleware)
3. [Middleware Pipeline Configuration](#middleware-pipeline-configuration)
4. [Request Processing Flow](#request-processing-flow)
5. [Response Processing](#response-processing)
6. [Performance Optimization](#performance-optimization)
7. [Error Handling and Resilience](#error-handling-and-resilience)
8. [Custom Middleware Development](#custom-middleware-development)
9. [Integration Patterns](#integration-patterns)
10. [Monitoring and Observability](#monitoring-and-observability)
11. [Testing Middleware](#testing-middleware)
12. [Advanced Scenarios](#advanced-scenarios)

## Middleware Architecture

### Security Middleware Stack

The SecurityFramework consists of multiple middleware components that work together to provide comprehensive protection:

```
┌─────────────────────────────────────┐
│         Request Pipeline            │
├─────────────────────────────────────┤
│  1. IP Security Middleware          │  ← First line of defense
├─────────────────────────────────────┤
│  2. Rate Limiting Middleware        │  ← Request frequency control
├─────────────────────────────────────┤
│  3. Pattern Matching Middleware     │  ← Threat pattern detection
├─────────────────────────────────────┤
│  4. Parameter Security Middleware   │  ← IDOR prevention
├─────────────────────────────────────┤
│  5. Behavioral Analysis Middleware  │  ← User behavior monitoring
├─────────────────────────────────────┤
│  6. Response Security Middleware    │  ← Output filtering
└─────────────────────────────────────┘
```

### Middleware Registration Order

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // 1. Early security middleware (before routing)
    app.UseSecurityFrameworkIPSecurity();
    app.UseSecurityFrameworkRateLimiting();
    
    // 2. Standard ASP.NET Core middleware
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();
    
    // 3. Late security middleware (after authentication/authorization)
    app.UseSecurityFrameworkPatternMatching();
    app.UseSecurityFrameworkParameterSecurity();
    app.UseSecurityFrameworkBehavioralAnalysis();
    
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
    
    // 4. Response middleware (after endpoint execution)
    app.UseSecurityFrameworkResponseSecurity();
}
```

### Middleware Dependencies

```csharp
public class MiddlewareDependencies
{
    public ISecurityService SecurityService { get; }
    public IIPReputationService IPReputationService { get; }
    public IPatternMatchingService PatternMatchingService { get; }
    public IBehavioralAnalysisService BehavioralAnalysisService { get; }
    public IParameterSecurityService ParameterSecurityService { get; }
    public IRateLimitingService RateLimitingService { get; }
    public ISecurityEventLogger EventLogger { get; }
    public ISecurityConfiguration Configuration { get; }
    public IMemoryCache Cache { get; }
    public ILogger Logger { get; }
}
```

## Core Security Middleware

### 1. IP Security Middleware

#### Implementation
```csharp
public class IPSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IIPSecurityService _ipSecurityService;
    private readonly ISecurityConfiguration _config;
    private readonly ILogger<IPSecurityMiddleware> _logger;
    
    public IPSecurityMiddleware(
        RequestDelegate next,
        IIPSecurityService ipSecurityService,
        ISecurityConfiguration config,
        ILogger<IPSecurityMiddleware> logger)
    {
        _next = next;
        _ipSecurityService = ipSecurityService;
        _config = config;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        var clientIP = GetClientIPAddress(context);
        
        if (string.IsNullOrEmpty(clientIP))
        {
            await _next(context);
            return;
        }
        
        // Check if IP is in trusted ranges
        if (IsTrustedIP(clientIP))
        {
            context.Items["SecurityFramework.TrustedIP"] = true;
            await _next(context);
            return;
        }
        
        // Perform IP reputation check
        var ipAssessment = await _ipSecurityService.AssessIPAsync(clientIP);
        
        // Store assessment in context for downstream middleware
        context.Items["SecurityFramework.IPAssessment"] = ipAssessment;
        
        // Handle blocked IPs
        if (ipAssessment.IsBlocked)
        {
            await HandleBlockedIPAsync(context, clientIP, ipAssessment);
            return;
        }
        
        // Handle high-risk IPs
        if (ipAssessment.ThreatScore > _config.IPSecurity.AutoBlockThreshold)
        {
            await HandleHighRiskIPAsync(context, clientIP, ipAssessment);
            return;
        }
        
        await _next(context);
    }
    
    private string GetClientIPAddress(HttpContext context)
    {
        // Check X-Forwarded-For header (from load balancers/proxies)
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            var ips = forwardedFor.Split(',');
            return ips[0].Trim(); // First IP is the original client
        }
        
        // Check X-Real-IP header
        var realIP = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIP))
        {
            return realIP;
        }
        
        // Fallback to connection remote IP
        return context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
    }
    
    private async Task HandleBlockedIPAsync(HttpContext context, string clientIP, IPAssessment assessment)
    {
        _logger.LogWarning("Blocked IP {ClientIP} attempted access. Reason: {Reason}", 
            clientIP, assessment.BlockReason);
            
        await LogSecurityEventAsync(context, "IPBlocked", assessment);
        
        context.Response.StatusCode = 403;
        context.Response.Headers["X-Security-Block-Reason"] = assessment.BlockReason ?? "IP blocked";
        
        await context.Response.WriteAsync("Access denied");
    }
}
```

#### Configuration
```csharp
public class IPSecurityOptions
{
    public bool EnableIPSecurity { get; set; } = true;
    public bool EnableBlocklist { get; set; } = true;
    public bool AutoBlockEnabled { get; set; } = false;
    public double AutoBlockThreshold { get; set; } = 75;
    public TimeSpan AutoBlockDuration { get; set; } = TimeSpan.FromHours(24);
    public bool EnableGeoBlocking { get; set; } = false;
    public List<string> TrustedIPRanges { get; set; } = new();
    public List<string> BlockedCountries { get; set; } = new();
    public bool AllowPrivateNetworks { get; set; } = true;
}
```

### 2. Rate Limiting Middleware

#### Implementation
```csharp
public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IRateLimitingService _rateLimitingService;
    private readonly ISecurityConfiguration _config;
    private readonly ILogger<RateLimitingMiddleware> _logger;
    
    public RateLimitingMiddleware(
        RequestDelegate next,
        IRateLimitingService rateLimitingService,
        ISecurityConfiguration config,
        ILogger<RateLimitingMiddleware> logger)
    {
        _next = next;
        _rateLimitingService = rateLimitingService;
        _config = config;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (!_config.IPSecurity.RateLimit.EnableRateLimit)
        {
            await _next(context);
            return;
        }
        
        var clientIP = context.Items["SecurityFramework.ClientIP"]?.ToString() 
            ?? GetClientIPAddress(context);
            
        var rateLimitResult = await _rateLimitingService.CheckRateLimitAsync(
            clientIP, 
            context.Request.Path,
            context.User?.Identity?.Name);
            
        // Add rate limit headers
        AddRateLimitHeaders(context, rateLimitResult);
        
        if (rateLimitResult.IsLimitExceeded)
        {
            await HandleRateLimitExceededAsync(context, rateLimitResult);
            return;
        }
        
        // Store rate limit info for downstream middleware
        context.Items["SecurityFramework.RateLimit"] = rateLimitResult;
        
        await _next(context);
    }
    
    private void AddRateLimitHeaders(HttpContext context, RateLimitResult result)
    {
        context.Response.Headers["X-RateLimit-Limit"] = result.Limit.ToString();
        context.Response.Headers["X-RateLimit-Remaining"] = result.Remaining.ToString();
        context.Response.Headers["X-RateLimit-Reset"] = result.ResetTime.ToString();
        
        if (result.IsLimitExceeded)
        {
            context.Response.Headers["Retry-After"] = result.RetryAfter.ToString();
        }
    }
    
    private async Task HandleRateLimitExceededAsync(HttpContext context, RateLimitResult result)
    {
        _logger.LogWarning("Rate limit exceeded for {ClientIP}. Limit: {Limit}, Current: {Current}",
            context.Items["SecurityFramework.ClientIP"], result.Limit, result.Current);
            
        await LogSecurityEventAsync(context, "RateLimitExceeded", result);
        
        context.Response.StatusCode = 429; // Too Many Requests
        
        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            error = "Rate limit exceeded",
            limit = result.Limit,
            remaining = result.Remaining,
            resetTime = result.ResetTime,
            retryAfter = result.RetryAfter
        }));
    }
}
```

### 3. Pattern Matching Middleware

#### Implementation
```csharp
public class PatternMatchingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPatternMatchingService _patternMatchingService;
    private readonly ISecurityConfiguration _config;
    private readonly ILogger<PatternMatchingMiddleware> _logger;
    
    public PatternMatchingMiddleware(
        RequestDelegate next,
        IPatternMatchingService patternMatchingService,
        ISecurityConfiguration config,
        ILogger<PatternMatchingMiddleware> logger)
    {
        _next = next;
        _patternMatchingService = patternMatchingService;
        _config = config;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (!_config.Patterns.EnablePatternMatching)
        {
            await _next(context);
            return;
        }
        
        // Extract request data for pattern matching
        var requestData = await ExtractRequestDataAsync(context);
        
        // Perform pattern matching
        var patternMatches = await _patternMatchingService.MatchPatternsAsync(requestData);
        
        // Store matches in context
        context.Items["SecurityFramework.PatternMatches"] = patternMatches;
        
        // Calculate pattern-based threat score
        var patternThreatScore = CalculatePatternThreatScore(patternMatches);
        
        // Handle high-threat patterns
        if (patternThreatScore > _config.DefaultThreatThreshold)
        {
            await HandleThreatPatternAsync(context, patternMatches, patternThreatScore);
            return;
        }
        
        await _next(context);
    }
    
    private async Task<RequestData> ExtractRequestDataAsync(HttpContext context)
    {
        var request = context.Request;
        
        // Read body if present
        string? requestBody = null;
        if (request.ContentLength > 0 && request.ContentLength < 1024 * 1024) // Max 1MB
        {
            request.EnableBuffering(); // Allow multiple reads
            using var reader = new StreamReader(request.Body, leaveOpen: true);
            requestBody = await reader.ReadToEndAsync();
            request.Body.Position = 0; // Reset for downstream middleware
        }
        
        return new RequestData
        {
            Method = request.Method,
            Path = request.Path.Value ?? string.Empty,
            QueryString = request.QueryString.Value ?? string.Empty,
            Headers = request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
            Body = requestBody,
            UserAgent = request.Headers["User-Agent"].FirstOrDefault(),
            Referrer = request.Headers["Referer"].FirstOrDefault(),
            ContentType = request.ContentType
        };
    }
    
    private double CalculatePatternThreatScore(List<PatternMatch> matches)
    {
        if (!matches.Any()) return 0;
        
        // Use logarithmic aggregation to prevent score inflation
        var weightedSum = matches.Sum(m => m.ThreatMultiplier * m.Confidence);
        var totalWeight = matches.Sum(m => m.Confidence);
        
        if (totalWeight == 0) return 0;
        
        var averageScore = weightedSum / totalWeight;
        
        // Apply diminishing returns for multiple matches
        var diminishingFactor = 1 - Math.Exp(-matches.Count / 3.0);
        
        return Math.Min(100, averageScore * diminishingFactor);
    }
}
```

### 4. Parameter Security Middleware

#### Implementation
```csharp
public class ParameterSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IParameterSecurityService _parameterSecurityService;
    private readonly ISecurityConfiguration _config;
    private readonly ILogger<ParameterSecurityMiddleware> _logger;
    
    public ParameterSecurityMiddleware(
        RequestDelegate next,
        IParameterSecurityService parameterSecurityService,
        ISecurityConfiguration config,
        ILogger<ParameterSecurityMiddleware> logger)
    {
        _next = next;
        _parameterSecurityService = parameterSecurityService;
        _config = config;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (!_config.ParameterSecurity.EnableParameterJackingDetection)
        {
            await _next(context);
            return;
        }
        
        // Extract and validate parameters
        var parameterValidationResult = await ValidateParametersAsync(context);
        
        // Store validation result
        context.Items["SecurityFramework.ParameterValidation"] = parameterValidationResult;
        
        // Handle parameter jacking attempts
        if (parameterValidationResult.HasViolations)
        {
            await HandleParameterViolationAsync(context, parameterValidationResult);
            return;
        }
        
        await _next(context);
    }
    
    private async Task<ParameterValidationResult> ValidateParametersAsync(HttpContext context)
    {
        var parameters = ExtractParameters(context);
        var userContext = GetUserContext(context);
        
        var violations = new List<ParameterViolation>();
        
        foreach (var parameter in parameters)
        {
            var validationResult = await _parameterSecurityService.ValidateParameterAsync(
                parameter, userContext);
                
            if (validationResult.IsViolation)
            {
                violations.Add(new ParameterViolation
                {
                    ParameterName = parameter.Name,
                    AttemptedValue = parameter.Value,
                    ViolationType = validationResult.ViolationType,
                    RiskScore = validationResult.RiskScore,
                    Description = validationResult.Description
                });
            }
        }
        
        return new ParameterValidationResult
        {
            Parameters = parameters,
            Violations = violations,
            HasViolations = violations.Any(),
            OverallRiskScore = violations.Any() ? violations.Max(v => v.RiskScore) : 0
        };
    }
    
    private List<RequestParameter> ExtractParameters(HttpContext context)
    {
        var parameters = new List<RequestParameter>();
        
        // Route parameters
        if (context.Request.RouteValues != null)
        {
            foreach (var routeValue in context.Request.RouteValues)
            {
                parameters.Add(new RequestParameter
                {
                    Name = routeValue.Key,
                    Value = routeValue.Value?.ToString() ?? string.Empty,
                    Source = ParameterSource.Route
                });
            }
        }
        
        // Query parameters
        foreach (var queryParam in context.Request.Query)
        {
            parameters.Add(new RequestParameter
            {
                Name = queryParam.Key,
                Value = queryParam.Value.ToString(),
                Source = ParameterSource.Query
            });
        }
        
        // Form parameters (if applicable)
        if (context.Request.HasFormContentType)
        {
            foreach (var formParam in context.Request.Form)
            {
                parameters.Add(new RequestParameter
                {
                    Name = formParam.Key,
                    Value = formParam.Value.ToString(),
                    Source = ParameterSource.Form
                });
            }
        }
        
        return parameters;
    }
}
```

### 5. Behavioral Analysis Middleware

#### Implementation
```csharp
public class BehavioralAnalysisMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IBehavioralAnalysisService _behavioralAnalysisService;
    private readonly ISecurityConfiguration _config;
    private readonly ILogger<BehavioralAnalysisMiddleware> _logger;
    
    public BehavioralAnalysisMiddleware(
        RequestDelegate next,
        IBehavioralAnalysisService behavioralAnalysisService,
        ISecurityConfiguration config,
        ILogger<BehavioralAnalysisMiddleware> logger)
    {
        _next = next;
        _behavioralAnalysisService = behavioralAnalysisService;
        _config = config;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Collect behavioral data
        var behaviorData = CollectBehaviorData(context);
        
        // Analyze behavior patterns
        var behaviorAnalysis = await _behavioralAnalysisService.AnalyzeBehaviorAsync(behaviorData);
        
        // Store analysis result
        context.Items["SecurityFramework.BehaviorAnalysis"] = behaviorAnalysis;
        
        // Handle anomalous behavior
        if (behaviorAnalysis.IsAnomalous && behaviorAnalysis.AnomalyScore > 70)
        {
            await HandleAnomalousBehaviorAsync(context, behaviorAnalysis);
        }
        
        await _next(context);
        
        // Record behavior data after request completion
        await RecordBehaviorDataAsync(context, behaviorData, behaviorAnalysis);
    }
    
    private BehaviorData CollectBehaviorData(HttpContext context)
    {
        var clientIP = context.Items["SecurityFramework.ClientIP"]?.ToString();
        var userId = context.User?.Identity?.Name;
        
        return new BehaviorData
        {
            ClientIP = clientIP,
            UserId = userId,
            Timestamp = DateTime.UtcNow,
            RequestPath = context.Request.Path.Value,
            RequestMethod = context.Request.Method,
            UserAgent = context.Request.Headers["User-Agent"].FirstOrDefault(),
            Referrer = context.Request.Headers["Referer"].FirstOrDefault(),
            SessionId = context.Session?.Id,
            ContentLength = context.Request.ContentLength,
            IsAuthenticated = context.User?.Identity?.IsAuthenticated ?? false,
            Roles = context.User?.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList() ?? new List<string>()
        };
    }
}
```

## Middleware Pipeline Configuration

### Service Registration
```csharp
public static class SecurityFrameworkServiceCollectionExtensions
{
    public static IServiceCollection AddSecurityFramework(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Configuration
        services.Configure<SecurityFrameworkOptions>(
            configuration.GetSection("SecurityFramework"));
            
        // Core services
        services.AddSingleton<ISecurityService, SecurityService>();
        services.AddSingleton<IIPSecurityService, IPSecurityService>();
        services.AddSingleton<IPatternMatchingService, PatternMatchingService>();
        services.AddSingleton<IBehavioralAnalysisService, BehavioralAnalysisService>();
        services.AddSingleton<IParameterSecurityService, ParameterSecurityService>();
        services.AddSingleton<IRateLimitingService, RateLimitingService>();
        
        // Data services
        services.AddDbContext<SecurityFrameworkDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("SecurityFramework");
            options.UseSqlite(connectionString);
        });
        
        // Repositories
        services.AddScoped<IIPSecurityRepository, IPSecurityRepository>();
        services.AddScoped<ISecurityEventRepository, SecurityEventRepository>();
        services.AddScoped<IThreatPatternRepository, ThreatPatternRepository>();
        
        // Background services
        services.AddHostedService<SecurityDataMaintenanceService>();
        services.AddHostedService<PatternReloadService>();
        
        // Caching
        services.AddMemoryCache();
        
        return services;
    }
}
```

### Middleware Registration Extensions
```csharp
public static class SecurityFrameworkApplicationBuilderExtensions
{
    public static IApplicationBuilder UseSecurityFramework(
        this IApplicationBuilder app,
        SecurityFrameworkMiddlewareOptions? options = null)
    {
        var config = app.ApplicationServices.GetRequiredService<IOptions<SecurityFrameworkOptions>>().Value;
        options ??= new SecurityFrameworkMiddlewareOptions();
        
        if (options.UseIPSecurity && config.IPSecurity.EnableBlocklist)
        {
            app.UseMiddleware<IPSecurityMiddleware>();
        }
        
        if (options.UseRateLimiting && config.IPSecurity.RateLimit.EnableRateLimit)
        {
            app.UseMiddleware<RateLimitingMiddleware>();
        }
        
        if (options.UsePatternMatching && config.Patterns.EnablePatternMatching)
        {
            app.UseMiddleware<PatternMatchingMiddleware>();
        }
        
        if (options.UseParameterSecurity && config.ParameterSecurity.EnableParameterJackingDetection)
        {
            app.UseMiddleware<ParameterSecurityMiddleware>();
        }
        
        if (options.UseBehavioralAnalysis)
        {
            app.UseMiddleware<BehavioralAnalysisMiddleware>();
        }
        
        return app;
    }
    
    // Individual middleware registration methods
    public static IApplicationBuilder UseSecurityFrameworkIPSecurity(this IApplicationBuilder app)
        => app.UseMiddleware<IPSecurityMiddleware>();
        
    public static IApplicationBuilder UseSecurityFrameworkRateLimiting(this IApplicationBuilder app)
        => app.UseMiddleware<RateLimitingMiddleware>();
        
    public static IApplicationBuilder UseSecurityFrameworkPatternMatching(this IApplicationBuilder app)
        => app.UseMiddleware<PatternMatchingMiddleware>();
        
    public static IApplicationBuilder UseSecurityFrameworkParameterSecurity(this IApplicationBuilder app)
        => app.UseMiddleware<ParameterSecurityMiddleware>();
        
    public static IApplicationBuilder UseSecurityFrameworkBehavioralAnalysis(this IApplicationBuilder app)
        => app.UseMiddleware<BehavioralAnalysisMiddleware>();
}
```

### Configuration Options
```csharp
public class SecurityFrameworkMiddlewareOptions
{
    public bool UseIPSecurity { get; set; } = true;
    public bool UseRateLimiting { get; set; } = true;
    public bool UsePatternMatching { get; set; } = true;
    public bool UseParameterSecurity { get; set; } = true;
    public bool UseBehavioralAnalysis { get; set; } = true;
    public bool UseResponseSecurity { get; set; } = true;
    
    public IPSecurityMiddlewareOptions IPSecurity { get; set; } = new();
    public RateLimitingMiddlewareOptions RateLimiting { get; set; } = new();
    public PatternMatchingMiddlewareOptions PatternMatching { get; set; } = new();
    public ParameterSecurityMiddlewareOptions ParameterSecurity { get; set; } = new();
    public BehavioralAnalysisMiddlewareOptions BehavioralAnalysis { get; set; } = new();
}
```

## Request Processing Flow

### Complete Request Flow
```csharp
public class SecurityFrameworkRequestFlow
{
    public async Task<SecurityAssessment> ProcessRequestAsync(HttpContext context)
    {
        var assessment = new SecurityAssessment
        {
            RequestId = Guid.NewGuid().ToString(),
            Timestamp = DateTime.UtcNow,
            ClientIP = GetClientIP(context),
            RequestPath = context.Request.Path.Value,
            UserAgent = context.Request.Headers["User-Agent"].FirstOrDefault()
        };
        
        // Phase 1: IP-based assessment
        var ipAssessment = await AssessIPSecurityAsync(context, assessment);
        assessment.IPAssessment = ipAssessment;
        
        if (ipAssessment.IsBlocked)
        {
            assessment.FinalAction = SecurityAction.Block;
            assessment.BlockReason = ipAssessment.BlockReason;
            return assessment;
        }
        
        // Phase 2: Rate limiting check
        var rateLimitResult = await CheckRateLimitAsync(context, assessment);
        assessment.RateLimitResult = rateLimitResult;
        
        if (rateLimitResult.IsLimitExceeded)
        {
            assessment.FinalAction = SecurityAction.Block;
            assessment.BlockReason = "Rate limit exceeded";
            return assessment;
        }
        
        // Phase 3: Pattern matching analysis
        var patternMatches = await AnalyzePatternsAsync(context, assessment);
        assessment.PatternMatches = patternMatches;
        
        // Phase 4: Parameter security validation
        var parameterValidation = await ValidateParametersAsync(context, assessment);
        assessment.ParameterValidation = parameterValidation;
        
        // Phase 5: Behavioral analysis
        var behaviorAnalysis = await AnalyzeBehaviorAsync(context, assessment);
        assessment.BehaviorAnalysis = behaviorAnalysis;
        
        // Phase 6: Composite scoring
        var compositeScore = await CalculateCompositeScoreAsync(assessment);
        assessment.CompositeScore = compositeScore;
        
        // Phase 7: Final action determination
        assessment.FinalAction = DetermineFinalAction(compositeScore);
        
        return assessment;
    }
    
    private SecurityAction DetermineFinalAction(CompositeScore score)
    {
        return score.OverallScore switch
        {
            >= 80 => SecurityAction.Block,
            >= 60 => SecurityAction.Challenge,
            >= 40 => SecurityAction.Monitor,
            _ => SecurityAction.Allow
        };
    }
}
```

### Request Context Management
```csharp
public class SecurityRequestContext
{
    public string RequestId { get; set; } = Guid.NewGuid().ToString();
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public string ClientIP { get; set; } = string.Empty;
    public string? UserId { get; set; }
    public string? SessionId { get; set; }
    public string RequestPath { get; set; } = string.Empty;
    public string RequestMethod { get; set; } = string.Empty;
    public Dictionary<string, object> Properties { get; set; } = new();
    
    // Security assessments
    public IPAssessment? IPAssessment { get; set; }
    public RateLimitResult? RateLimitResult { get; set; }
    public List<PatternMatch> PatternMatches { get; set; } = new();
    public ParameterValidationResult? ParameterValidation { get; set; }
    public BehaviorAnalysis? BehaviorAnalysis { get; set; }
    public CompositeScore? CompositeScore { get; set; }
    
    // Final decision
    public SecurityAction FinalAction { get; set; } = SecurityAction.Allow;
    public string? BlockReason { get; set; }
    public double OverallThreatScore { get; set; }
    
    public void SetProperty<T>(string key, T value) => Properties[key] = value!;
    public T? GetProperty<T>(string key) => Properties.TryGetValue(key, out var value) ? (T)value : default;
}
```

## Response Processing

### Response Security Middleware
```csharp
public class ResponseSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IResponseSecurityService _responseSecurityService;
    private readonly ISecurityConfiguration _config;
    private readonly ILogger<ResponseSecurityMiddleware> _logger;
    
    public ResponseSecurityMiddleware(
        RequestDelegate next,
        IResponseSecurityService responseSecurityService,
        ISecurityConfiguration config,
        ILogger<ResponseSecurityMiddleware> logger)
    {
        _next = next;
        _responseSecurityService = responseSecurityService;
        _config = config;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Capture the original response body stream
        var originalBodyStream = context.Response.Body;
        
        using var responseBody = new MemoryStream();
        context.Response.Body = responseBody;
        
        try
        {
            await _next(context);
            
            // Analyze response for security issues
            var responseAnalysis = await AnalyzeResponseAsync(context, responseBody);
            
            // Apply security headers
            ApplySecurityHeaders(context, responseAnalysis);
            
            // Filter sensitive data if needed
            var filteredResponse = await FilterSensitiveDataAsync(responseBody, responseAnalysis);
            
            // Write the processed response
            await WriteResponseAsync(originalBodyStream, filteredResponse);
        }
        finally
        {
            context.Response.Body = originalBodyStream;
        }
    }
    
    private async Task<ResponseAnalysis> AnalyzeResponseAsync(HttpContext context, MemoryStream responseBody)
    {
        responseBody.Seek(0, SeekOrigin.Begin);
        var responseContent = await new StreamReader(responseBody).ReadToEndAsync();
        responseBody.Seek(0, SeekOrigin.Begin);
        
        var analysis = new ResponseAnalysis
        {
            StatusCode = context.Response.StatusCode,
            ContentType = context.Response.ContentType,
            ContentLength = responseBody.Length,
            Content = responseContent
        };
        
        // Check for sensitive data exposure
        analysis.SensitiveDataExposure = await _responseSecurityService
            .DetectSensitiveDataAsync(responseContent);
            
        // Check for information leakage
        analysis.InformationLeakage = await _responseSecurityService
            .DetectInformationLeakageAsync(context, responseContent);
            
        return analysis;
    }
    
    private void ApplySecurityHeaders(HttpContext context, ResponseAnalysis analysis)
    {
        var response = context.Response;
        
        // Security headers
        if (!response.Headers.ContainsKey("X-Content-Type-Options"))
            response.Headers["X-Content-Type-Options"] = "nosniff";
            
        if (!response.Headers.ContainsKey("X-Frame-Options"))
            response.Headers["X-Frame-Options"] = "DENY";
            
        if (!response.Headers.ContainsKey("X-XSS-Protection"))
            response.Headers["X-XSS-Protection"] = "1; mode=block";
            
        if (!response.Headers.ContainsKey("Referrer-Policy"))
            response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            
        // Content Security Policy
        if (!response.Headers.ContainsKey("Content-Security-Policy"))
        {
            var csp = BuildContentSecurityPolicy(context, analysis);
            response.Headers["Content-Security-Policy"] = csp;
        }
        
        // HSTS for HTTPS responses
        if (context.Request.IsHttps && !response.Headers.ContainsKey("Strict-Transport-Security"))
        {
            response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        }
        
        // Security Framework identification
        response.Headers["X-Security-Framework"] = "SecurityFramework/1.0";
    }
}
```

### Response Filtering
```csharp
public class ResponseFilteringService
{
    private readonly ILogger<ResponseFilteringService> _logger;
    private readonly List<ISensitiveDataDetector> _sensitiveDataDetectors;
    
    public async Task<string> FilterSensitiveDataAsync(string responseContent, ResponseAnalysis analysis)
    {
        if (!analysis.SensitiveDataExposure.HasSensitiveData)
            return responseContent;
            
        var filteredContent = responseContent;
        
        foreach (var exposure in analysis.SensitiveDataExposure.Exposures)
        {
            filteredContent = await ApplyFilterAsync(filteredContent, exposure);
        }
        
        return filteredContent;
    }
    
    private async Task<string> ApplyFilterAsync(string content, SensitiveDataExposure exposure)
    {
        return exposure.Type switch
        {
            SensitiveDataType.CreditCard => FilterCreditCardNumbers(content),
            SensitiveDataType.SocialSecurityNumber => FilterSSNs(content),
            SensitiveDataType.EmailAddress => FilterEmailAddresses(content),
            SensitiveDataType.PhoneNumber => FilterPhoneNumbers(content),
            SensitiveDataType.IPAddress => FilterIPAddresses(content),
            SensitiveDataType.DatabaseConnection => FilterConnectionStrings(content),
            _ => content
        };
    }
    
    private string FilterCreditCardNumbers(string content)
    {
        // Mask credit card numbers (keep first 4 and last 4 digits)
        var creditCardPattern = @"\b(?:\d{4}[-\s]?){3}\d{4}\b";
        return Regex.Replace(content, creditCardPattern, match =>
        {
            var digits = Regex.Replace(match.Value, @"[-\s]", "");
            if (digits.Length >= 8)
            {
                var first4 = digits.Substring(0, 4);
                var last4 = digits.Substring(digits.Length - 4);
                return $"{first4}****{last4}";
            }
            return "****";
        });
    }
}
```

## Performance Optimization

### Caching Strategies
```csharp
public class SecurityFrameworkCacheManager
{
    private readonly IMemoryCache _memoryCache;
    private readonly IDistributedCache _distributedCache;
    private readonly ILogger<SecurityFrameworkCacheManager> _logger;
    
    public async Task<T?> GetOrSetAsync<T>(
        string key, 
        Func<Task<T>> factory, 
        TimeSpan? expiration = null) where T : class
    {
        // Check memory cache first
        if (_memoryCache.TryGetValue(key, out T? cached))
        {
            return cached;
        }
        
        // Check distributed cache
        var distributedValue = await _distributedCache.GetStringAsync(key);
        if (!string.IsNullOrEmpty(distributedValue))
        {
            try
            {
                var deserialized = JsonSerializer.Deserialize<T>(distributedValue);
                if (deserialized != null)
                {
                    // Cache in memory for faster access
                    _memoryCache.Set(key, deserialized, TimeSpan.FromMinutes(5));
                    return deserialized;
                }
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Failed to deserialize cached value for key {Key}", key);
            }
        }
        
        // Generate new value
        var newValue = await factory();
        if (newValue != null)
        {
            var serialized = JsonSerializer.Serialize(newValue);
            
            // Cache in both memory and distributed cache
            _memoryCache.Set(key, newValue, expiration ?? TimeSpan.FromMinutes(15));
            await _distributedCache.SetStringAsync(key, serialized, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = expiration ?? TimeSpan.FromHours(1)
            });
        }
        
        return newValue;
    }
    
    public void InvalidatePattern(string pattern)
    {
        // Implement cache invalidation by pattern
        if (_memoryCache is MemoryCache mc)
        {
            var field = typeof(MemoryCache).GetField("_coherentState", 
                BindingFlags.NonPublic | BindingFlags.Instance);
            if (field?.GetValue(mc) is IDictionary dict)
            {
                var keysToRemove = dict.Keys
                    .OfType<string>()
                    .Where(key => key.Contains(pattern))
                    .ToList();
                    
                foreach (var key in keysToRemove)
                {
                    _memoryCache.Remove(key);
                }
            }
        }
    }
}
```

### Asynchronous Processing
```csharp
public class AsynchronousSecurityProcessor
{
    private readonly Channel<SecurityEvent> _eventChannel;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AsynchronousSecurityProcessor> _logger;
    
    public AsynchronousSecurityProcessor(
        IServiceProvider serviceProvider,
        ILogger<AsynchronousSecurityProcessor> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        
        var options = new BoundedChannelOptions(10000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false
        };
        
        _eventChannel = Channel.CreateBounded<SecurityEvent>(options);
        
        // Start background processing
        _ = Task.Run(ProcessEventsAsync);
    }
    
    public async Task<bool> EnqueueEventAsync(SecurityEvent securityEvent)
    {
        try
        {
            await _eventChannel.Writer.WriteAsync(securityEvent);
            return true;
        }
        catch (InvalidOperationException)
        {
            _logger.LogWarning("Failed to enqueue security event - channel is closed");
            return false;
        }
    }
    
    private async Task ProcessEventsAsync()
    {
        await foreach (var securityEvent in _eventChannel.Reader.ReadAllAsync())
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var eventProcessor = scope.ServiceProvider.GetRequiredService<ISecurityEventProcessor>();
                
                await eventProcessor.ProcessEventAsync(securityEvent);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process security event {EventId}", securityEvent.EventId);
            }
        }
    }
}
```

### Connection Pooling
```csharp
public class SecurityFrameworkDbContextPooling
{
    public static void ConfigureDbContextPool(IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContextPool<SecurityFrameworkDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("SecurityFramework");
            options.UseSqlite(connectionString, sqliteOptions =>
            {
                sqliteOptions.CommandTimeout(30);
            });
            
            // Optimize for read-heavy workloads
            options.EnableSensitiveDataLogging(false);
            options.EnableServiceProviderCaching(true);
            options.EnableDetailedErrors(false);
            
        }, poolSize: 100); // Pool size based on expected concurrency
    }
}
```

## Error Handling and Resilience

### Exception Handling Middleware
```csharp
public class SecurityFrameworkExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityFrameworkExceptionMiddleware> _logger;
    private readonly SecurityFrameworkOptions _options;
    
    public SecurityFrameworkExceptionMiddleware(
        RequestDelegate next,
        ILogger<SecurityFrameworkExceptionMiddleware> logger,
        IOptions<SecurityFrameworkOptions> options)
    {
        _next = next;
        _logger = logger;
        _options = options.Value;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (SecurityFrameworkException sfex)
        {
            await HandleSecurityFrameworkExceptionAsync(context, sfex);
        }
        catch (Exception ex)
        {
            await HandleGenericExceptionAsync(context, ex);
        }
    }
    
    private async Task HandleSecurityFrameworkExceptionAsync(
        HttpContext context, 
        SecurityFrameworkException exception)
    {
        _logger.LogError(exception, "SecurityFramework exception occurred: {Message}", exception.Message);
        
        // Don't expose internal security details
        var response = new
        {
            error = "Security processing error",
            requestId = context.TraceIdentifier,
            timestamp = DateTime.UtcNow
        };
        
        context.Response.StatusCode = exception.StatusCode;
        context.Response.ContentType = "application/json";
        
        await context.Response.WriteAsync(JsonSerializer.Serialize(response));
    }
    
    private async Task HandleGenericExceptionAsync(HttpContext context, Exception exception)
    {
        _logger.LogError(exception, "Unhandled exception in SecurityFramework");
        
        // Fail open - allow request to continue if configured
        if (_options.FailOpen)
        {
            _logger.LogWarning("Failing open due to unhandled exception");
            await _next(context);
            return;
        }
        
        // Fail closed - return error response
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        
        var response = new
        {
            error = "Internal security error",
            requestId = context.TraceIdentifier
        };
        
        await context.Response.WriteAsync(JsonSerializer.Serialize(response));
    }
}
```

### Circuit Breaker Pattern
```csharp
public class SecurityServiceCircuitBreaker
{
    private readonly CircuitBreakerState _state = new();
    private readonly ILogger<SecurityServiceCircuitBreaker> _logger;
    
    public async Task<T> ExecuteAsync<T>(Func<Task<T>> operation, T fallbackValue)
    {
        if (_state.State == CircuitState.Open)
        {
            if (_state.ShouldAttemptReset())
            {
                _state.State = CircuitState.HalfOpen;
            }
            else
            {
                _logger.LogWarning("Circuit breaker is open, returning fallback value");
                return fallbackValue;
            }
        }
        
        try
        {
            var result = await operation();
            _state.OnSuccess();
            return result;
        }
        catch (Exception ex)
        {
            _state.OnFailure();
            _logger.LogError(ex, "Operation failed, circuit breaker failure count: {FailureCount}", 
                _state.FailureCount);
                
            if (_state.State == CircuitState.Open)
            {
                _logger.LogWarning("Circuit breaker opened due to repeated failures");
            }
            
            return fallbackValue;
        }
    }
}

public class CircuitBreakerState
{
    private readonly int _failureThreshold = 5;
    private readonly TimeSpan _timeout = TimeSpan.FromMinutes(1);
    
    public CircuitState State { get; set; } = CircuitState.Closed;
    public int FailureCount { get; private set; }
    public DateTime LastFailureTime { get; private set; }
    
    public void OnSuccess()
    {
        FailureCount = 0;
        State = CircuitState.Closed;
    }
    
    public void OnFailure()
    {
        FailureCount++;
        LastFailureTime = DateTime.UtcNow;
        
        if (FailureCount >= _failureThreshold)
        {
            State = CircuitState.Open;
        }
    }
    
    public bool ShouldAttemptReset()
    {
        return State == CircuitState.Open && 
               DateTime.UtcNow - LastFailureTime >= _timeout;
    }
}
```

## Custom Middleware Development

### Base Security Middleware
```csharp
public abstract class BaseSecurityMiddleware
{
    protected readonly RequestDelegate Next;
    protected readonly ILogger Logger;
    protected readonly SecurityFrameworkOptions Options;
    
    protected BaseSecurityMiddleware(
        RequestDelegate next,
        ILogger logger,
        IOptions<SecurityFrameworkOptions> options)
    {
        Next = next;
        Logger = logger;
        Options = options.Value;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (!ShouldProcess(context))
        {
            await Next(context);
            return;
        }
        
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            var result = await ProcessSecurityAsync(context);
            
            if (result.ShouldBlock)
            {
                await HandleBlockedRequestAsync(context, result);
                return;
            }
            
            // Store result for downstream middleware
            StoreResult(context, result);
            
            await Next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
        finally
        {
            stopwatch.Stop();
            LogPerformance(context, stopwatch.ElapsedMilliseconds);
        }
    }
    
    protected abstract Task<SecurityResult> ProcessSecurityAsync(HttpContext context);
    
    protected virtual bool ShouldProcess(HttpContext context)
    {
        // Skip processing for certain paths
        var path = context.Request.Path.Value?.ToLowerInvariant();
        
        var skipPaths = new[]
        {
            "/health",
            "/metrics",
            "/favicon.ico",
            "/.well-known/"
        };
        
        return !skipPaths.Any(skipPath => path?.StartsWith(skipPath) == true);
    }
    
    protected virtual void StoreResult(HttpContext context, SecurityResult result)
    {
        var key = $"SecurityFramework.{GetType().Name}";
        context.Items[key] = result;
    }
    
    protected virtual async Task HandleBlockedRequestAsync(HttpContext context, SecurityResult result)
    {
        Logger.LogWarning("Request blocked by {MiddlewareName}: {Reason}", 
            GetType().Name, result.BlockReason);
            
        context.Response.StatusCode = result.StatusCode;
        await context.Response.WriteAsync(result.BlockReason ?? "Request blocked");
    }
    
    protected virtual async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        Logger.LogError(exception, "Error in {MiddlewareName}", GetType().Name);
        
        if (Options.FailOpen)
        {
            await Next(context);
        }
        else
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Security processing error");
        }
    }
    
    protected virtual void LogPerformance(HttpContext context, long elapsedMs)
    {
        if (elapsedMs > 100) // Log slow operations
        {
            Logger.LogWarning("{MiddlewareName} took {ElapsedMs}ms for {Path}", 
                GetType().Name, elapsedMs, context.Request.Path);
        }
    }
}
```

### Custom Middleware Example
```csharp
public class CustomThreatDetectionMiddleware : BaseSecurityMiddleware
{
    private readonly ICustomThreatDetectionService _threatDetectionService;
    
    public CustomThreatDetectionMiddleware(
        RequestDelegate next,
        ICustomThreatDetectionService threatDetectionService,
        ILogger<CustomThreatDetectionMiddleware> logger,
        IOptions<SecurityFrameworkOptions> options) 
        : base(next, logger, options)
    {
        _threatDetectionService = threatDetectionService;
    }
    
    protected override async Task<SecurityResult> ProcessSecurityAsync(HttpContext context)
    {
        var requestData = await ExtractRequestDataAsync(context);
        var threatAnalysis = await _threatDetectionService.AnalyzeRequestAsync(requestData);
        
        return new SecurityResult
        {
            ShouldBlock = threatAnalysis.ThreatScore > 80,
            StatusCode = 403,
            BlockReason = threatAnalysis.ThreatDescription,
            ThreatScore = threatAnalysis.ThreatScore,
            AdditionalData = threatAnalysis.Details
        };
    }
    
    private async Task<CustomRequestData> ExtractRequestDataAsync(HttpContext context)
    {
        // Custom request data extraction logic
        return new CustomRequestData
        {
            Path = context.Request.Path.Value,
            Method = context.Request.Method,
            Headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
            ClientIP = GetClientIP(context),
            // Additional custom data extraction
        };
    }
}
```

## Integration Patterns

### Integration with ASP.NET Core Authentication
```csharp
public class AuthenticationIntegratedSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ISecurityService _securityService;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Wait for authentication to complete
        await _next(context);
        
        // Perform security analysis with authentication context
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var userSecurityContext = new UserSecurityContext
            {
                UserId = context.User.Identity.Name,
                Roles = context.User.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
                    .ToList(),
                AuthenticationMethod = context.User.Identity.AuthenticationType,
                IsAuthenticated = true
            };
            
            var userThreatAssessment = await _securityService
                .AssessUserThreatAsync(userSecurityContext, context);
                
            if (userThreatAssessment.RequiresAdditionalVerification)
            {
                await ChallengeUserAsync(context, userThreatAssessment);
            }
        }
    }
}
```

### Integration with Authorization
```csharp
public class SecurityFrameworkAuthorizationHandler : AuthorizationHandler<SecurityRequirement>
{
    private readonly ISecurityService _securityService;
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SecurityRequirement requirement)
    {
        if (context.Resource is HttpContext httpContext)
        {
            var securityContext = httpContext.Items["SecurityFramework.Context"] as SecurityRequestContext;
            
            if (securityContext?.OverallThreatScore > requirement.MaxThreatScore)
            {
                context.Fail();
                return;
            }
            
            if (securityContext?.FinalAction == SecurityAction.Block)
            {
                context.Fail();
                return;
            }
        }
        
        context.Succeed(requirement);
    }
}

public class SecurityRequirement : IAuthorizationRequirement
{
    public double MaxThreatScore { get; set; } = 50;
    public List<SecurityAction> AllowedActions { get; set; } = new()
    {
        SecurityAction.Allow,
        SecurityAction.Monitor
    };
}
```

### Integration with MVC Filters
```csharp
public class SecurityFrameworkActionFilter : IAsyncActionFilter
{
    private readonly ISecurityService _securityService;
    
    public async Task OnActionExecutionAsync(
        ActionExecutingContext context,
        ActionExecutionDelegate next)
    {
        // Pre-action security checks
        var securityResult = await PerformActionSecurityChecksAsync(context);
        
        if (securityResult.ShouldBlock)
        {
            context.Result = new ForbidResult(securityResult.BlockReason);
            return;
        }
        
        var executedContext = await next();
        
        // Post-action security analysis
        await PerformPostActionAnalysisAsync(executedContext);
    }
    
    private async Task<ActionSecurityResult> PerformActionSecurityChecksAsync(
        ActionExecutingContext context)
    {
        var actionDescriptor = context.ActionDescriptor;
        var securityRequirements = GetSecurityRequirements(actionDescriptor);
        
        return await _securityService.ValidateActionSecurityAsync(
            context.HttpContext, securityRequirements);
    }
}
```

## Monitoring and Observability

### Performance Metrics
```csharp
public class SecurityFrameworkMetrics
{
    private readonly IMetricsLogger _metrics;
    
    [Counter]
    public static readonly Counter RequestsProcessed = Metrics
        .CreateCounter("securityframework_requests_processed_total",
            "Total number of requests processed by SecurityFramework");
            
    [Counter]
    public static readonly Counter ThreatsDetected = Metrics
        .CreateCounter("securityframework_threats_detected_total",
            "Total number of threats detected");
            
    [Counter]
    public static readonly Counter RequestsBlocked = Metrics
        .CreateCounter("securityframework_requests_blocked_total",
            "Total number of requests blocked");
            
    [Histogram]
    public static readonly Histogram ProcessingTime = Metrics
        .CreateHistogram("securityframework_processing_time_ms",
            "Time taken to process security checks in milliseconds");
            
    [Histogram]
    public static readonly Histogram ThreatScores = Metrics
        .CreateHistogram("securityframework_threat_scores",
            "Distribution of threat scores");
    
    public void RecordRequestProcessed(string middleware, double processingTimeMs, double threatScore)
    {
        RequestsProcessed.WithTag("middleware", middleware).Increment();
        ProcessingTime.WithTag("middleware", middleware).Observe(processingTimeMs);
        ThreatScores.Observe(threatScore);
    }
    
    public void RecordThreatDetected(string threatType, string severity)
    {
        ThreatsDetected
            .WithTag("type", threatType)
            .WithTag("severity", severity)
            .Increment();
    }
    
    public void RecordRequestBlocked(string reason, string middleware)
    {
        RequestsBlocked
            .WithTag("reason", reason)
            .WithTag("middleware", middleware)
            .Increment();
    }
}
```

### Health Checks
```csharp
public class SecurityFrameworkHealthCheck : IHealthCheck
{
    private readonly ISecurityService _securityService;
    private readonly SecurityFrameworkDbContext _dbContext;
    private readonly IMemoryCache _cache;
    
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var healthData = new Dictionary<string, object>();
        
        try
        {
            // Check database connectivity
            var dbHealthy = await CheckDatabaseHealthAsync();
            healthData["database"] = dbHealthy ? "healthy" : "unhealthy";
            
            // Check pattern loading
            var patternsHealthy = await CheckPatternsHealthAsync();
            healthData["patterns"] = patternsHealthy ? "healthy" : "unhealthy";
            
            // Check cache
            var cacheHealthy = CheckCacheHealth();
            healthData["cache"] = cacheHealthy ? "healthy" : "unhealthy";
            
            // Check performance metrics
            var performanceMetrics = await GetPerformanceMetricsAsync();
            healthData["performance"] = performanceMetrics;
            
            var isHealthy = dbHealthy && patternsHealthy && cacheHealthy;
            
            return isHealthy
                ? HealthCheckResult.Healthy("SecurityFramework is healthy", healthData)
                : HealthCheckResult.Degraded("SecurityFramework has issues", healthData);
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("SecurityFramework is unhealthy", ex, healthData);
        }
    }
    
    private async Task<bool> CheckDatabaseHealthAsync()
    {
        try
        {
            await _dbContext.Database.CanConnectAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
```

### Distributed Tracing
```csharp
public class SecurityFrameworkTracing
{
    private static readonly ActivitySource ActivitySource = new("SecurityFramework");
    
    public static Activity? StartActivity(string name)
    {
        return ActivitySource.StartActivity($"SecurityFramework.{name}");
    }
    
    public static void RecordSecurityEvent(Activity? activity, SecurityEvent securityEvent)
    {
        activity?.SetTag("security.event.type", securityEvent.EventType);
        activity?.SetTag("security.threat.score", securityEvent.ThreatScore.ToString());
        activity?.SetTag("security.client.ip", securityEvent.ClientIP);
        activity?.SetTag("security.action.taken", securityEvent.ActionTaken);
    }
    
    public static void RecordException(Activity? activity, Exception exception)
    {
        activity?.SetStatus(ActivityStatusCode.Error, exception.Message);
        activity?.SetTag("error.type", exception.GetType().Name);
        activity?.SetTag("error.message", exception.Message);
    }
}
```

## Testing Middleware

### Unit Testing Middleware
```csharp
public class IPSecurityMiddlewareTests
{
    private readonly Mock<IIPSecurityService> _mockIPSecurityService;
    private readonly Mock<ISecurityConfiguration> _mockConfig;
    private readonly Mock<ILogger<IPSecurityMiddleware>> _mockLogger;
    
    public IPSecurityMiddlewareTests()
    {
        _mockIPSecurityService = new Mock<IIPSecurityService>();
        _mockConfig = new Mock<ISecurityConfiguration>();
        _mockLogger = new Mock<ILogger<IPSecurityMiddleware>>();
    }
    
    [Fact]
    public async Task InvokeAsync_BlockedIP_Returns403()
    {
        // Arrange
        var context = CreateHttpContext("192.168.1.100");
        var assessment = new IPAssessment
        {
            IsBlocked = true,
            BlockReason = "Malicious IP"
        };
        
        _mockIPSecurityService.Setup(x => x.AssessIPAsync("192.168.1.100"))
            .ReturnsAsync(assessment);
            
        var middleware = new IPSecurityMiddleware(
            ctx => Task.CompletedTask,
            _mockIPSecurityService.Object,
            _mockConfig.Object,
            _mockLogger.Object);
        
        // Act
        await middleware.InvokeAsync(context);
        
        // Assert
        Assert.Equal(403, context.Response.StatusCode);
    }
    
    [Fact]
    public async Task InvokeAsync_TrustedIP_SkipsAssessment()
    {
        // Arrange
        var context = CreateHttpContext("127.0.0.1");
        var middleware = new IPSecurityMiddleware(
            ctx => Task.CompletedTask,
            _mockIPSecurityService.Object,
            _mockConfig.Object,
            _mockLogger.Object);
        
        // Act
        await middleware.InvokeAsync(context);
        
        // Assert
        _mockIPSecurityService.Verify(x => x.AssessIPAsync(It.IsAny<string>()), Times.Never);
    }
    
    private HttpContext CreateHttpContext(string clientIP)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(clientIP);
        context.Response.Body = new MemoryStream();
        return context;
    }
}
```

### Integration Testing
```csharp
public class SecurityFrameworkIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;
    
    public SecurityFrameworkIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Replace services with test doubles
                services.AddSingleton<IIPSecurityService, TestIPSecurityService>();
            });
        });
        
        _client = _factory.CreateClient();
    }
    
    [Fact]
    public async Task Request_WithMaliciousPattern_ReturnsBlocked()
    {
        // Arrange
        var maliciousPayload = "'; DROP TABLE Users; --";
        
        // Act
        var response = await _client.GetAsync($"/api/search?q={maliciousPayload}");
        
        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
    
    [Theory]
    [InlineData("/api/users/1")]
    [InlineData("/api/orders/123")]
    public async Task Request_WithParameterJacking_ReturnsBlocked(string path)
    {
        // Arrange & Act
        var response = await _client.GetAsync(path);
        
        // Assert based on test setup
        // This would depend on your test data configuration
    }
}
```

## Advanced Scenarios

### Custom Security Policies
```csharp
public class CustomSecurityPolicy
{
    public string Name { get; set; } = string.Empty;
    public List<SecurityRule> Rules { get; set; } = new();
    public SecurityAction DefaultAction { get; set; } = SecurityAction.Allow;
    
    public async Task<SecurityPolicyResult> EvaluateAsync(SecurityRequestContext context)
    {
        var ruleResults = new List<SecurityRuleResult>();
        
        foreach (var rule in Rules)
        {
            var result = await rule.EvaluateAsync(context);
            ruleResults.Add(result);
            
            if (result.Action == SecurityAction.Block)
            {
                return new SecurityPolicyResult
                {
                    Action = SecurityAction.Block,
                    Reason = result.Reason,
                    MatchedRule = rule
                };
            }
        }
        
        return new SecurityPolicyResult
        {
            Action = DefaultAction,
            RuleResults = ruleResults
        };
    }
}
```

### Multi-Tenant Security
```csharp
public class MultiTenantSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITenantSecurityConfigurationProvider _tenantConfigProvider;
    
    public async Task InvokeAsync(HttpContext context)
    {
        var tenantId = ExtractTenantId(context);
        var tenantConfig = await _tenantConfigProvider.GetConfigurationAsync(tenantId);
        
        // Apply tenant-specific security configuration
        context.Items["SecurityFramework.TenantConfig"] = tenantConfig;
        
        // Proceed with tenant-aware security processing
        await _next(context);
    }
    
    private string ExtractTenantId(HttpContext context)
    {
        // Extract from subdomain
        var host = context.Request.Host.Host;
        var subdomain = host.Split('.')[0];
        
        // Or extract from header
        var tenantHeader = context.Request.Headers["X-Tenant-ID"].FirstOrDefault();
        
        // Or extract from path
        var pathSegments = context.Request.Path.Value?.Split('/');
        
        return tenantHeader ?? subdomain ?? pathSegments?[1] ?? "default";
    }
}
```

---

This Middleware documentation provides comprehensive coverage of the SecurityFramework's middleware architecture, implementation details, configuration options, and integration patterns. The middleware components work together to provide seamless, high-performance security protection for ASP.NET Core applications.