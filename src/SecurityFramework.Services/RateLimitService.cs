using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityFramework.Core.Abstractions;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace SecurityFramework.Services;

/// <summary>
/// Service for managing rate limiting and throttling
/// </summary>
public class RateLimitService : IRateLimitService
{
    private readonly ILogger<RateLimitService> _logger;
    private readonly IMemoryCache _cache;
    private readonly RateLimitOptions _options;
    private readonly ConcurrentDictionary<string, RateLimitPolicy> _policies;
    private readonly ConcurrentDictionary<string, RateLimitCounter> _counters;
    private readonly ConcurrentDictionary<string, TokenBucket> _tokenBuckets;
    private readonly Timer _cleanupTimer;
    private readonly RateLimitStatistics _statistics;

    public RateLimitService(
        ILogger<RateLimitService> logger,
        IMemoryCache cache,
        IOptions<RateLimitOptions> options)
    {
        _logger = logger;
        _cache = cache;
        _options = options.Value;
        _policies = new ConcurrentDictionary<string, RateLimitPolicy>();
        _counters = new ConcurrentDictionary<string, RateLimitCounter>();
        _tokenBuckets = new ConcurrentDictionary<string, TokenBucket>();
        _statistics = new RateLimitStatistics();

        // Initialize default policies
        InitializeDefaultPolicies();

        // Setup cleanup timer to remove expired entries
        _cleanupTimer = new Timer(CleanupExpiredEntries, null, 
            _options.CleanupInterval, _options.CleanupInterval);
    }

    public async Task<RateLimitResult> CheckRateLimitAsync(string key, RateLimitPolicy policy, CancellationToken cancellationToken = default)
    {
        if (!policy.IsEnabled)
        {
            return new RateLimitResult
            {
                IsAllowed = true,
                Reason = "Policy is disabled",
                PolicyName = policy.Name
            };
        }

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var result = policy.Algorithm switch
            {
                RateLimitAlgorithm.FixedWindow => CheckFixedWindow(key, policy),
                RateLimitAlgorithm.SlidingWindow => CheckSlidingWindow(key, policy),
                RateLimitAlgorithm.TokenBucket => CheckTokenBucket(key, policy),
                RateLimitAlgorithm.LeakyBucket => CheckLeakyBucket(key, policy),
                RateLimitAlgorithm.SlidingWindowLog => CheckSlidingWindowLog(key, policy),
                RateLimitAlgorithm.Adaptive => CheckAdaptive(key, policy),
                _ => throw new NotSupportedException($"Algorithm {policy.Algorithm} is not supported")
            };

            // Update statistics
            _statistics.TotalRequests++;
            if (result.IsAllowed)
            {
                _statistics.AllowedRequests++;
            }
            else
            {
                _statistics.BlockedRequests++;
            }

            return result;
        }
        finally
        {
            stopwatch.Stop();
            UpdatePerformanceMetrics(stopwatch.ElapsedMilliseconds);
        }
    }

    public RateLimitResult CheckRateLimit(string key, RateLimitPolicy policy)
    {
        return CheckRateLimitAsync(key, policy).GetAwaiter().GetResult();
    }

    public async Task RecordRequestAsync(string key, RateLimitPolicy policy, int cost = 1, CancellationToken cancellationToken = default)
    {
        var counterKey = GetCounterKey(key, policy.Name);
        var counter = _counters.GetOrAdd(counterKey, _ => new RateLimitCounter
        {
            Key = key,
            PolicyName = policy.Name,
            WindowStart = GetWindowStart(policy.Window),
            Count = 0
        });

        lock (counter)
        {
            var currentWindowStart = GetWindowStart(policy.Window);
            if (counter.WindowStart != currentWindowStart)
            {
                // Reset counter for new window
                counter.WindowStart = currentWindowStart;
                counter.Count = 0;
            }

            counter.Count += cost;
            counter.LastRequest = DateTime.UtcNow;
            counter.TotalRequests += cost;
        }

        _logger.LogDebug("Recorded {Cost} requests for key {Key} under policy {Policy}. Current count: {Count}", 
            cost, key, policy.Name, counter.Count);
    }

    public async Task<RateLimitStatus> GetStatusAsync(string key, RateLimitPolicy policy, CancellationToken cancellationToken = default)
    {
        var counterKey = GetCounterKey(key, policy.Name);
        var counter = _counters.GetOrAdd(counterKey, _ => new RateLimitCounter
        {
            Key = key,
            PolicyName = policy.Name,
            WindowStart = GetWindowStart(policy.Window),
            Count = 0
        });

        var windowStart = GetWindowStart(policy.Window);
        var windowEnd = windowStart.Add(policy.Window);

        return new RateLimitStatus
        {
            Key = key,
            PolicyName = policy.Name,
            CurrentCount = counter.Count,
            Limit = policy.Limit,
            WindowStart = windowStart,
            WindowEnd = windowEnd,
            IsRateLimited = counter.Count >= policy.Limit,
            RateLimitedSince = counter.Count >= policy.Limit ? counter.FirstExceeded : null,
            LastRequest = counter.LastRequest,
            TotalRequests = counter.TotalRequests
        };
    }

    public async Task ResetRateLimitAsync(string key, RateLimitPolicy policy, CancellationToken cancellationToken = default)
    {
        var counterKey = GetCounterKey(key, policy.Name);
        if (_counters.TryRemove(counterKey, out var counter))
        {
            _logger.LogInformation("Reset rate limit for key {Key} under policy {Policy}", key, policy.Name);
        }

        // Also reset token bucket if applicable
        if (policy.Algorithm == RateLimitAlgorithm.TokenBucket)
        {
            var bucketKey = GetBucketKey(key, policy.Name);
            if (_tokenBuckets.TryRemove(bucketKey, out var bucket))
            {
                _logger.LogDebug("Reset token bucket for key {Key} under policy {Policy}", key, policy.Name);
            }
        }
    }

    public async Task<RateLimitStatistics> GetStatisticsAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default)
    {
        var stats = new RateLimitStatistics
        {
            TimePeriod = timeWindow ?? TimeSpan.FromHours(1),
            TotalRequests = _statistics.TotalRequests,
            AllowedRequests = _statistics.AllowedRequests,
            BlockedRequests = _statistics.BlockedRequests,
            UniqueRateLimitedKeys = _counters.Values.Count(c => c.Count >= GetPolicyByName(c.PolicyName)?.Limit),
            PolicyStatistics = _statistics.PolicyStatistics.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            Performance = _statistics.Performance
        };

        // Calculate top rate limited keys
        stats.TopRateLimitedKeys = _counters.Values
            .Where(c => c.Count > 0)
            .GroupBy(c => c.Key)
            .Select(g => new TopRateLimitedKey
            {
                Key = g.Key,
                TotalRequests = g.Sum(c => c.TotalRequests),
                BlockedRequests = g.Sum(c => Math.Max(0, c.Count - (GetPolicyByName(c.PolicyName)?.Limit ?? 0))),
                AffectedPolicies = g.Select(c => c.PolicyName).Distinct().ToList(),
                FirstSeen = g.Min(c => c.FirstRequest ?? DateTime.UtcNow),
                LastSeen = g.Max(c => c.LastRequest ?? DateTime.UtcNow)
            })
            .OrderByDescending(k => k.BlockedRequests)
            .Take(10)
            .ToList();

        return stats;
    }

    public async Task SetPolicyAsync(RateLimitPolicy policy, CancellationToken cancellationToken = default)
    {
        _policies.AddOrUpdate(policy.Name, policy, (key, existing) => policy);
        _logger.LogInformation("Added/updated rate limit policy {PolicyName}", policy.Name);
    }

    public async Task RemovePolicyAsync(string policyName, CancellationToken cancellationToken = default)
    {
        if (_policies.TryRemove(policyName, out var policy))
        {
            // Clean up associated counters
            var keysToRemove = _counters.Keys.Where(k => k.EndsWith($":{policyName}")).ToList();
            foreach (var key in keysToRemove)
            {
                _counters.TryRemove(key, out _);
            }

            _logger.LogInformation("Removed rate limit policy {PolicyName}", policyName);
        }
    }

    public async Task<IEnumerable<RateLimitPolicy>> GetPoliciesAsync(CancellationToken cancellationToken = default)
    {
        return _policies.Values.Where(p => p.IsEnabled);
    }

    // Rate limiting algorithm implementations

    private RateLimitResult CheckFixedWindow(string key, RateLimitPolicy policy)
    {
        var counterKey = GetCounterKey(key, policy.Name);
        var counter = _counters.GetOrAdd(counterKey, _ => new RateLimitCounter
        {
            Key = key,
            PolicyName = policy.Name,
            WindowStart = GetWindowStart(policy.Window),
            Count = 0
        });

        lock (counter)
        {
            var currentWindowStart = GetWindowStart(policy.Window);
            if (counter.WindowStart != currentWindowStart)
            {
                // Reset counter for new window
                counter.WindowStart = currentWindowStart;
                counter.Count = 0;
                counter.FirstExceeded = null;
            }

            var isAllowed = counter.Count < policy.Limit;
            if (!isAllowed && counter.FirstExceeded == null)
            {
                counter.FirstExceeded = DateTime.UtcNow;
            }

            if (isAllowed)
            {
                counter.Count++;
                counter.LastRequest = DateTime.UtcNow;
                if (counter.FirstRequest == null)
                    counter.FirstRequest = DateTime.UtcNow;
            }

            var resetTime = counter.WindowStart.Add(policy.Window);

            return new RateLimitResult
            {
                IsAllowed = isAllowed,
                Reason = isAllowed ? "Request allowed" : "Rate limit exceeded",
                CurrentCount = counter.Count,
                Limit = policy.Limit,
                ResetTime = resetTime,
                RetryAfter = isAllowed ? null : resetTime - DateTime.UtcNow,
                PolicyName = policy.Name
            };
        }
    }

    private RateLimitResult CheckSlidingWindow(string key, RateLimitPolicy policy)
    {
        var cacheKey = $"sliding_{key}_{policy.Name}";
        var requests = _cache.GetOrCreate(cacheKey, entry =>
        {
            entry.SlidingExpiration = policy.Window;
            return new List<DateTime>();
        }) ?? new List<DateTime>();

        lock (requests)
        {
            var cutoff = DateTime.UtcNow - policy.Window;
            requests.RemoveAll(r => r < cutoff);

            var isAllowed = requests.Count < policy.Limit;
            if (isAllowed)
            {
                requests.Add(DateTime.UtcNow);
            }

            var oldestRequest = requests.Any() ? requests.Min() : DateTime.UtcNow;
            var resetTime = oldestRequest.Add(policy.Window);

            return new RateLimitResult
            {
                IsAllowed = isAllowed,
                Reason = isAllowed ? "Request allowed" : "Rate limit exceeded",
                CurrentCount = requests.Count,
                Limit = policy.Limit,
                ResetTime = resetTime,
                RetryAfter = isAllowed ? null : resetTime - DateTime.UtcNow,
                PolicyName = policy.Name
            };
        }
    }

    private RateLimitResult CheckTokenBucket(string key, RateLimitPolicy policy)
    {
        var bucketKey = GetBucketKey(key, policy.Name);
        var bucket = _tokenBuckets.GetOrAdd(bucketKey, _ => new TokenBucket
        {
            Capacity = policy.Limit,
            Tokens = policy.Limit,
            RefillRate = policy.Limit / policy.Window.TotalSeconds,
            LastRefill = DateTime.UtcNow
        });

        lock (bucket)
        {
            // Refill tokens based on time elapsed
            var now = DateTime.UtcNow;
            var elapsed = (now - bucket.LastRefill).TotalSeconds;
            var tokensToAdd = elapsed * bucket.RefillRate;
            
            bucket.Tokens = Math.Min(bucket.Capacity, bucket.Tokens + tokensToAdd);
            bucket.LastRefill = now;

            var isAllowed = bucket.Tokens >= 1;
            if (isAllowed)
            {
                bucket.Tokens--;
            }

            var resetTime = now.AddSeconds((1 - bucket.Tokens) / bucket.RefillRate);

            return new RateLimitResult
            {
                IsAllowed = isAllowed,
                Reason = isAllowed ? "Token available" : "No tokens available",
                CurrentCount = (long)(bucket.Capacity - bucket.Tokens),
                Limit = (long)bucket.Capacity,
                ResetTime = resetTime,
                RetryAfter = isAllowed ? null : TimeSpan.FromSeconds(1 / bucket.RefillRate),
                PolicyName = policy.Name
            };
        }
    }

    private RateLimitResult CheckLeakyBucket(string key, RateLimitPolicy policy)
    {
        // Simplified leaky bucket implementation
        var bucketKey = GetBucketKey(key, policy.Name);
        var bucket = _tokenBuckets.GetOrAdd(bucketKey, _ => new TokenBucket
        {
            Capacity = policy.Limit,
            Tokens = 0,
            RefillRate = 1.0 / policy.Window.TotalSeconds,
            LastRefill = DateTime.UtcNow
        });

        lock (bucket)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - bucket.LastRefill).TotalSeconds;
            
            // Leak tokens
            bucket.Tokens = Math.Max(0, bucket.Tokens - elapsed * bucket.RefillRate);
            bucket.LastRefill = now;

            var isAllowed = bucket.Tokens < bucket.Capacity;
            if (isAllowed)
            {
                bucket.Tokens++;
            }

            var resetTime = now.AddSeconds((bucket.Tokens - bucket.Capacity + 1) / bucket.RefillRate);

            return new RateLimitResult
            {
                IsAllowed = isAllowed,
                Reason = isAllowed ? "Bucket not full" : "Bucket overflow",
                CurrentCount = (long)bucket.Tokens,
                Limit = (long)bucket.Capacity,
                ResetTime = resetTime,
                RetryAfter = isAllowed ? null : TimeSpan.FromSeconds(1 / bucket.RefillRate),
                PolicyName = policy.Name
            };
        }
    }

    private RateLimitResult CheckSlidingWindowLog(string key, RateLimitPolicy policy)
    {
        // Similar to sliding window but with more precise tracking
        return CheckSlidingWindow(key, policy);
    }

    private RateLimitResult CheckAdaptive(string key, RateLimitPolicy policy)
    {
        // Adaptive rate limiting based on system load and threat level
        var baseResult = CheckFixedWindow(key, policy);
        
        // Adjust limits based on current system state
        var adaptiveFactor = CalculateAdaptiveFactor(key, policy);
        var adjustedLimit = (long)(policy.Limit * adaptiveFactor);
        
        baseResult.Limit = adjustedLimit;
        baseResult.IsAllowed = baseResult.CurrentCount < adjustedLimit;
        baseResult.Reason = baseResult.IsAllowed ? 
            $"Adaptive limit: {adjustedLimit}" : 
            $"Adaptive rate limit exceeded: {adjustedLimit}";

        return baseResult;
    }

    // Helper methods

    private void InitializeDefaultPolicies()
    {
        var defaultPolicies = new[]
        {
            new RateLimitPolicy
            {
                Name = "Default",
                Algorithm = RateLimitAlgorithm.FixedWindow,
                Limit = 100,
                Window = TimeSpan.FromMinutes(1),
                Description = "Default rate limiting policy"
            },
            new RateLimitPolicy
            {
                Name = "Strict",
                Algorithm = RateLimitAlgorithm.SlidingWindow,
                Limit = 10,
                Window = TimeSpan.FromMinutes(1),
                Description = "Strict rate limiting for suspicious activity"
            },
            new RateLimitPolicy
            {
                Name = "TokenBucketDefault",
                Algorithm = RateLimitAlgorithm.TokenBucket,
                Limit = 50,
                Window = TimeSpan.FromMinutes(1),
                Description = "Token bucket rate limiting"
            }
        };

        foreach (var policy in defaultPolicies)
        {
            _policies.TryAdd(policy.Name, policy);
        }
    }

    private string GetCounterKey(string key, string policyName)
    {
        return $"{key}:{policyName}";
    }

    private string GetBucketKey(string key, string policyName)
    {
        return $"bucket_{key}_{policyName}";
    }

    private DateTime GetWindowStart(TimeSpan window)
    {
        var now = DateTime.UtcNow;
        var ticks = now.Ticks / window.Ticks;
        return new DateTime(ticks * window.Ticks, DateTimeKind.Utc);
    }

    private RateLimitPolicy? GetPolicyByName(string policyName)
    {
        _policies.TryGetValue(policyName, out var policy);
        return policy;
    }

    private double CalculateAdaptiveFactor(string key, RateLimitPolicy policy)
    {
        // Simplified adaptive factor calculation
        // In production, this would consider system load, threat intelligence, etc.
        var baseload = Environment.ProcessorCount > 0 ? 
            GC.GetTotalMemory(false) / (Environment.ProcessorCount * 1024 * 1024) : 1.0;
        
        var loadFactor = Math.Max(0.1, Math.Min(2.0, 1.0 - (baseload / 100.0)));
        
        // Check if this key has been involved in security incidents
        var threatFactor = key.Contains("suspicious") ? 0.5 : 1.0; // Simplified
        
        return loadFactor * threatFactor;
    }

    private void UpdatePerformanceMetrics(long elapsedMs)
    {
        var performance = _statistics.Performance;
        performance.AverageCheckTime = (performance.AverageCheckTime + elapsedMs) / 2;
        
        // Update percentiles (simplified)
        if (elapsedMs > performance.P99CheckTime)
            performance.P99CheckTime = elapsedMs;
        if (elapsedMs > performance.P95CheckTime)
            performance.P95CheckTime = Math.Max(performance.P95CheckTime, elapsedMs * 0.95);
    }

    private void CleanupExpiredEntries(object? state)
    {
        var cutoff = DateTime.UtcNow - _options.CounterRetentionPeriod;
        var expiredKeys = _counters
            .Where(kvp => kvp.Value.LastRequest < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            _counters.TryRemove(key, out _);
        }

        if (expiredKeys.Count > 0)
        {
            _logger.LogDebug("Cleaned up {Count} expired rate limit counters", expiredKeys.Count);
        }
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
    }
}

/// <summary>
/// Rate limit counter for tracking requests
/// </summary>
internal class RateLimitCounter
{
    public string Key { get; set; } = "";
    public string PolicyName { get; set; } = "";
    public DateTime WindowStart { get; set; }
    public long Count { get; set; }
    public DateTime? FirstRequest { get; set; }
    public DateTime? LastRequest { get; set; }
    public DateTime? FirstExceeded { get; set; }
    public long TotalRequests { get; set; }
}

/// <summary>
/// Token bucket for token bucket algorithm
/// </summary>
internal class TokenBucket
{
    public double Capacity { get; set; }
    public double Tokens { get; set; }
    public double RefillRate { get; set; }
    public DateTime LastRefill { get; set; }
}

/// <summary>
/// Configuration options for rate limiting service
/// </summary>
public class RateLimitOptions
{
    /// <summary>
    /// How often to clean up expired counters
    /// </summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long to retain counter data after last request
    /// </summary>
    public TimeSpan CounterRetentionPeriod { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Whether to enable adaptive rate limiting
    /// </summary>
    public bool EnableAdaptiveLimiting { get; set; } = false;

    /// <summary>
    /// Default policy to use when none is specified
    /// </summary>
    public string DefaultPolicyName { get; set; } = "Default";

    /// <summary>
    /// Whether to include rate limiting headers in responses
    /// </summary>
    public bool IncludeHeaders { get; set; } = true;

    /// <summary>
    /// Maximum number of counters to keep in memory
    /// </summary>
    public int MaxCounters { get; set; } = 100000;

    /// <summary>
    /// Whether to log rate limiting decisions
    /// </summary>
    public bool LogDecisions { get; set; } = false;
}