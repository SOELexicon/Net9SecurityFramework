using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityFramework.Core.Abstractions;
using System.Net;
using System.Text.Json;

namespace SecurityFramework.Middleware;

/// <summary>
/// Middleware for applying rate limiting to HTTP requests
/// </summary>
public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitMiddleware> _logger;
    private readonly IRateLimitService _rateLimitService;
    private readonly RateLimitMiddlewareOptions _options;

    public RateLimitMiddleware(
        RequestDelegate next,
        ILogger<RateLimitMiddleware> logger,
        IRateLimitService rateLimitService,
        IOptions<RateLimitMiddlewareOptions> options)
    {
        _next = next;
        _logger = logger;
        _rateLimitService = rateLimitService;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.Enabled)
        {
            await _next(context);
            return;
        }

        // Skip rate limiting for excluded paths
        if (IsExcludedPath(context.Request.Path))
        {
            await _next(context);
            return;
        }

        try
        {
            var key = await GenerateRateLimitKeyAsync(context);
            var policy = await SelectPolicyAsync(context);

            if (policy == null)
            {
                _logger.LogDebug("No rate limiting policy found for request {Path}", context.Request.Path);
                await _next(context);
                return;
            }

            var result = await _rateLimitService.CheckRateLimitAsync(key, policy);

            // Add rate limiting headers
            if (_options.IncludeHeaders)
            {
                AddRateLimitHeaders(context.Response, result);
            }

            if (result.IsAllowed)
            {
                // Record the request
                await _rateLimitService.RecordRequestAsync(key, policy);
                
                // Continue to next middleware
                await _next(context);
            }
            else
            {
                // Request is rate limited
                await HandleRateLimitExceededAsync(context, result, policy);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in rate limiting middleware");
            
            if (_options.ContinueOnError)
            {
                await _next(context);
            }
            else
            {
                throw;
            }
        }
    }

    private async Task<string> GenerateRateLimitKeyAsync(HttpContext context)
    {
        var keyParts = new List<string>();

        // Add IP address if configured
        if (_options.KeyGenerationStrategy.IncludeIP)
        {
            var ip = GetClientIpAddress(context);
            keyParts.Add($"ip:{ip}");
        }

        // Add user ID if available and configured
        if (_options.KeyGenerationStrategy.IncludeUser && context.User.Identity?.IsAuthenticated == true)
        {
            var userId = context.User.Identity.Name ?? context.User.FindFirst("sub")?.Value ?? "anonymous";
            keyParts.Add($"user:{userId}");
        }

        // Add path if configured
        if (_options.KeyGenerationStrategy.IncludePath)
        {
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "/";
            keyParts.Add($"path:{path}");
        }

        // Add method if configured
        if (_options.KeyGenerationStrategy.IncludeMethod)
        {
            keyParts.Add($"method:{context.Request.Method}");
        }

        // Add custom headers if configured
        foreach (var header in _options.KeyGenerationStrategy.IncludeHeaders)
        {
            if (context.Request.Headers.TryGetValue(header, out var values))
            {
                keyParts.Add($"header:{header}:{values.FirstOrDefault()}");
            }
        }

        // Use custom key generator if provided
        if (_options.CustomKeyGenerator != null)
        {
            var customKey = await _options.CustomKeyGenerator(context);
            if (!string.IsNullOrEmpty(customKey))
            {
                keyParts.Add($"custom:{customKey}");
            }
        }

        return string.Join("|", keyParts);
    }

    private async Task<RateLimitPolicy?> SelectPolicyAsync(HttpContext context)
    {
        // Try policy selectors in order of priority
        foreach (var selector in _options.PolicySelectors.OrderByDescending(s => s.Priority))
        {
            if (await selector.AppliesAsync(context))
            {
                var policies = await _rateLimitService.GetPoliciesAsync();
                var policy = policies.FirstOrDefault(p => p.Name == selector.PolicyName);
                if (policy != null)
                {
                    return policy;
                }
            }
        }

        // Use default policy
        if (!string.IsNullOrEmpty(_options.DefaultPolicyName))
        {
            var policies = await _rateLimitService.GetPoliciesAsync();
            return policies.FirstOrDefault(p => p.Name == _options.DefaultPolicyName);
        }

        return null;
    }

    private async Task HandleRateLimitExceededAsync(HttpContext context, RateLimitResult result, RateLimitPolicy policy)
    {
        _logger.LogWarning("Rate limit exceeded for key {Key} under policy {Policy}. Current: {Current}, Limit: {Limit}", 
            await GenerateRateLimitKeyAsync(context), policy.Name, result.CurrentCount, result.Limit);

        // Execute configured actions
        foreach (var action in policy.Actions)
        {
            await ExecuteActionAsync(context, action, result);
        }

        // Set response status and content
        context.Response.StatusCode = _options.StatusCode;
        context.Response.ContentType = "application/json";

        var response = new
        {
            error = "Rate limit exceeded",
            message = _options.ErrorMessage,
            details = new
            {
                limit = result.Limit,
                current = result.CurrentCount,
                remaining = result.Remaining,
                reset_time = result.ResetTime,
                retry_after = result.RetryAfter?.TotalSeconds
            }
        };

        var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        await context.Response.WriteAsync(jsonResponse);
    }

    private async Task ExecuteActionAsync(HttpContext context, RateLimitAction action, RateLimitResult result)
    {
        switch (action.Type)
        {
            case ActionType.Block:
                // Already handled by returning rate limit response
                break;

            case ActionType.Log:
                var logLevel = action.Configuration.TryGetValue("level", out var level) && 
                              Enum.TryParse<LogLevel>(level.ToString(), out var parsedLevel) ? 
                              parsedLevel : LogLevel.Warning;
                
                _logger.Log(logLevel, "Rate limit action: {Action} for {IP} - {Message}", 
                    action.Type, GetClientIpAddress(context), result.Reason);
                break;

            case ActionType.Alert:
                // Send alert through notification service if available
                // This would require injecting INotificationService
                break;

            case ActionType.Throttle:
                var delay = action.Configuration.TryGetValue("delay", out var delayValue) && 
                           int.TryParse(delayValue.ToString(), out var delayMs) ? 
                           delayMs : 1000;
                
                await Task.Delay(delayMs);
                break;

            case ActionType.Redirect:
                if (action.Configuration.TryGetValue("url", out var redirectUrl))
                {
                    context.Response.Redirect(redirectUrl.ToString());
                }
                break;

            case ActionType.Challenge:
                // Implement challenge logic (CAPTCHA, etc.)
                context.Response.Headers.Add("X-Rate-Limit-Challenge", "required");
                break;

            case ActionType.Custom:
                // Execute custom action if handler is provided
                if (_options.CustomActionHandler != null)
                {
                    await _options.CustomActionHandler(context, action, result);
                }
                break;
        }
    }

    private void AddRateLimitHeaders(HttpResponse response, RateLimitResult result)
    {
        response.Headers.Add("X-RateLimit-Limit", result.Limit.ToString());
        response.Headers.Add("X-RateLimit-Remaining", result.Remaining.ToString());
        response.Headers.Add("X-RateLimit-Reset", ((DateTimeOffset)result.ResetTime).ToUnixTimeSeconds().ToString());
        response.Headers.Add("X-RateLimit-Policy", result.PolicyName);

        if (result.RetryAfter.HasValue)
        {
            response.Headers.Add("Retry-After", ((int)result.RetryAfter.Value.TotalSeconds).ToString());
        }
    }

    private string GetClientIpAddress(HttpContext context)
    {
        // Check for forwarded IP headers
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (ips.Length > 0)
            {
                return ips[0].Trim();
            }
        }

        var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private bool IsExcludedPath(PathString path)
    {
        return _options.ExcludedPaths.Any(excluded => 
            path.StartsWithSegments(excluded, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Configuration options for rate limiting middleware
/// </summary>
public class RateLimitMiddlewareOptions
{
    /// <summary>
    /// Whether rate limiting middleware is enabled
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// HTTP status code to return when rate limit is exceeded
    /// </summary>
    public int StatusCode { get; set; } = (int)HttpStatusCode.TooManyRequests;

    /// <summary>
    /// Error message to return when rate limit is exceeded
    /// </summary>
    public string ErrorMessage { get; set; } = "Too many requests. Please try again later.";

    /// <summary>
    /// Whether to include rate limiting headers in responses
    /// </summary>
    public bool IncludeHeaders { get; set; } = true;

    /// <summary>
    /// Whether to continue processing if an error occurs
    /// </summary>
    public bool ContinueOnError { get; set; } = true;

    /// <summary>
    /// Default policy name to use when no specific policy matches
    /// </summary>
    public string DefaultPolicyName { get; set; } = "Default";

    /// <summary>
    /// Strategy for generating rate limit keys
    /// </summary>
    public KeyGenerationStrategy KeyGenerationStrategy { get; set; } = new();

    /// <summary>
    /// Policy selectors for determining which policy to apply
    /// </summary>
    public List<PolicySelector> PolicySelectors { get; set; } = new();

    /// <summary>
    /// Paths to exclude from rate limiting
    /// </summary>
    public List<string> ExcludedPaths { get; set; } = new() { "/health", "/metrics" };

    /// <summary>
    /// Custom key generator function
    /// </summary>
    public Func<HttpContext, Task<string>>? CustomKeyGenerator { get; set; }

    /// <summary>
    /// Custom action handler for custom rate limit actions
    /// </summary>
    public Func<HttpContext, RateLimitAction, RateLimitResult, Task>? CustomActionHandler { get; set; }
}

/// <summary>
/// Strategy for generating rate limit keys
/// </summary>
public class KeyGenerationStrategy
{
    /// <summary>
    /// Include client IP address in the key
    /// </summary>
    public bool IncludeIP { get; set; } = true;

    /// <summary>
    /// Include user identifier in the key
    /// </summary>
    public bool IncludeUser { get; set; } = false;

    /// <summary>
    /// Include request path in the key
    /// </summary>
    public bool IncludePath { get; set; } = false;

    /// <summary>
    /// Include HTTP method in the key
    /// </summary>
    public bool IncludeMethod { get; set; } = false;

    /// <summary>
    /// Headers to include in the key
    /// </summary>
    public List<string> IncludeHeaders { get; set; } = new();
}

/// <summary>
/// Policy selector for determining which rate limit policy to apply
/// </summary>
public class PolicySelector
{
    /// <summary>
    /// Policy name to apply
    /// </summary>
    public string PolicyName { get; set; } = "";

    /// <summary>
    /// Priority of this selector (higher = more priority)
    /// </summary>
    public int Priority { get; set; } = 1;

    /// <summary>
    /// Function to determine if this selector applies to the request
    /// </summary>
    public Func<HttpContext, Task<bool>> AppliesAsync { get; set; } = _ => Task.FromResult(false);
}

/// <summary>
/// Extension methods for registering rate limiting middleware
/// </summary>
public static class RateLimitMiddlewareExtensions
{
    /// <summary>
    /// Adds rate limiting middleware to the pipeline
    /// </summary>
    public static IApplicationBuilder UseRateLimit(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RateLimitMiddleware>();
    }

    /// <summary>
    /// Adds rate limiting middleware with configuration
    /// </summary>
    public static IApplicationBuilder UseRateLimit(this IApplicationBuilder app, Action<RateLimitMiddlewareOptions> configure)
    {
        var options = new RateLimitMiddlewareOptions();
        configure(options);
        
        return app.UseMiddleware<RateLimitMiddleware>(Options.Create(options));
    }
}