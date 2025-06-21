using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityFramework.Core.Abstractions;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace SecurityFramework.Services;

/// <summary>
/// Service for managing IP blocklists from multiple sources
/// </summary>
public class BlocklistService : IBlocklistService
{
    private readonly ILogger<BlocklistService> _logger;
    private readonly IMemoryCache _cache;
    private readonly BlocklistOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ConcurrentDictionary<string, BlocklistEntry> _localBlocklist;
    private readonly ConcurrentDictionary<string, BlocklistSourceStatistics> _sourceStats;
    private readonly Timer _refreshTimer;
    private DateTime _lastRefresh = DateTime.MinValue;

    public BlocklistService(
        ILogger<BlocklistService> logger,
        IMemoryCache cache,
        IOptions<BlocklistOptions> options,
        HttpClient httpClient)
    {
        _logger = logger;
        _cache = cache;
        _options = options.Value;
        _httpClient = httpClient;
        _localBlocklist = new ConcurrentDictionary<string, BlocklistEntry>();
        _sourceStats = new ConcurrentDictionary<string, BlocklistSourceStatistics>();

        // Initialize HTTP client
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.HttpTimeoutSeconds);

        // Initialize source statistics
        foreach (var source in _options.Sources)
        {
            _sourceStats[source.Name] = new BlocklistSourceStatistics
            {
                Name = source.Name,
                IsActive = source.IsEnabled
            };
        }

        // Setup refresh timer
        _refreshTimer = new Timer(async _ => await RefreshBlocklistsAsync(), 
            null, TimeSpan.Zero, _options.RefreshInterval);
    }

    public async Task<BlocklistResult> IsBlockedAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            var result = await CheckAllSourcesAsync(ipAddress, cancellationToken);
            return result;
        }
        finally
        {
            stopwatch.Stop();
            // Update performance metrics
            foreach (var stat in _sourceStats.Values)
            {
                stat.AverageResponseTime = (stat.AverageResponseTime + stopwatch.ElapsedMilliseconds) / 2;
            }
        }
    }

    public BlocklistResult IsBlocked(string ipAddress)
    {
        // Check local blocklist first (fastest)
        var localResult = CheckLocalBlocklist(ipAddress);
        if (localResult.IsBlocked)
            return localResult;

        // Check cached results
        var cacheKey = $"blocklist_{ipAddress}";
        if (_cache.TryGetValue(cacheKey, out BlocklistResult? cachedResult) && cachedResult != null)
        {
            return cachedResult;
        }

        // Return not blocked if no cached result
        return new BlocklistResult { IsBlocked = false };
    }

    public async Task AddToBlocklistAsync(string ipAddress, string reason, DateTime? expiresAt = null, CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(ipAddress, out _))
        {
            throw new ArgumentException("Invalid IP address format", nameof(ipAddress));
        }

        var entry = new BlocklistEntry
        {
            IPOrRange = ipAddress,
            Type = BlocklistEntryType.IP,
            Source = "Local",
            Reason = reason,
            ExpiresAt = expiresAt,
            Categories = new List<string> { "Manual" }
        };

        _localBlocklist[ipAddress] = entry;
        
        // Invalidate cache
        _cache.Remove($"blocklist_{ipAddress}");

        _logger.LogInformation("Added IP {IPAddress} to local blocklist: {Reason}", ipAddress, reason);
    }

    public async Task RemoveFromBlocklistAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        if (_localBlocklist.TryRemove(ipAddress, out var entry))
        {
            // Invalidate cache
            _cache.Remove($"blocklist_{ipAddress}");
            
            _logger.LogInformation("Removed IP {IPAddress} from local blocklist", ipAddress);
        }
    }

    public async Task AddRangeToBlocklistAsync(string cidrRange, string reason, DateTime? expiresAt = null, CancellationToken cancellationToken = default)
    {
        if (!IsValidCIDR(cidrRange))
        {
            throw new ArgumentException("Invalid CIDR range format", nameof(cidrRange));
        }

        var entry = new BlocklistEntry
        {
            IPOrRange = cidrRange,
            Type = BlocklistEntryType.Range,
            Source = "Local",
            Reason = reason,
            ExpiresAt = expiresAt,
            Categories = new List<string> { "Manual" }
        };

        _localBlocklist[cidrRange] = entry;

        _logger.LogInformation("Added CIDR range {CIDRRange} to local blocklist: {Reason}", cidrRange, reason);
    }

    public async Task RemoveRangeFromBlocklistAsync(string cidrRange, CancellationToken cancellationToken = default)
    {
        if (_localBlocklist.TryRemove(cidrRange, out var entry))
        {
            _logger.LogInformation("Removed CIDR range {CIDRRange} from local blocklist", cidrRange);
        }
    }

    public async Task<BlocklistStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
    {
        var totalIPs = _localBlocklist.Values.Count(e => e.Type == BlocklistEntryType.IP && e.IsActive);
        var totalRanges = _localBlocklist.Values.Count(e => e.Type == BlocklistEntryType.Range && e.IsActive);

        return new BlocklistStatistics
        {
            TotalBlockedIPs = totalIPs,
            TotalBlockedRanges = totalRanges,
            ActiveSources = _sourceStats.Values.Count(s => s.IsActive),
            LastUpdate = _lastRefresh,
            AverageResponseTime = _sourceStats.Values.Average(s => s.AverageResponseTime),
            ChecksToday = GetTodayChecks(),
            BlocksToday = GetTodayBlocks(),
            SourceStatistics = _sourceStats.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
        };
    }

    public async Task RefreshBlocklistsAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting blocklist refresh from {SourceCount} sources", _options.Sources.Count);

        var refreshTasks = _options.Sources
            .Where(s => s.IsEnabled)
            .Select(source => RefreshFromSourceAsync(source, cancellationToken));

        await Task.WhenAll(refreshTasks);

        // Clean up expired entries
        CleanupExpiredEntries();

        _lastRefresh = DateTime.UtcNow;
        _logger.LogInformation("Completed blocklist refresh");
    }

    public async Task<IEnumerable<BlocklistEntry>> GetBlocklistEntriesAsync(CancellationToken cancellationToken = default)
    {
        return _localBlocklist.Values
            .Where(e => e.IsActive && (e.ExpiresAt == null || e.ExpiresAt > DateTime.UtcNow))
            .OrderByDescending(e => e.UpdatedAt);
    }

    private async Task<BlocklistResult> CheckAllSourcesAsync(string ipAddress, CancellationToken cancellationToken)
    {
        // Check local blocklist first
        var localResult = CheckLocalBlocklist(ipAddress);
        if (localResult.IsBlocked)
            return localResult;

        // Check cache
        var cacheKey = $"blocklist_{ipAddress}";
        if (_cache.TryGetValue(cacheKey, out BlocklistResult? cachedResult) && cachedResult != null)
        {
            return cachedResult;
        }

        // Check external sources if enabled
        if (_options.EnableExternalSources)
        {
            var externalTasks = _options.Sources
                .Where(s => s.IsEnabled && s.Type == BlocklistSourceType.External)
                .Select(source => CheckExternalSourceAsync(ipAddress, source, cancellationToken));

            var externalResults = await Task.WhenAll(externalTasks);
            var blockedResult = externalResults.FirstOrDefault(r => r.IsBlocked);
            
            if (blockedResult != null)
            {
                // Cache the result
                _cache.Set(cacheKey, blockedResult, _options.CacheDuration);
                return blockedResult;
            }
        }

        var notBlockedResult = new BlocklistResult { IsBlocked = false };
        _cache.Set(cacheKey, notBlockedResult, _options.CacheDuration);
        return notBlockedResult;
    }

    private BlocklistResult CheckLocalBlocklist(string ipAddress)
    {
        // Check exact IP match
        if (_localBlocklist.TryGetValue(ipAddress, out var exactMatch) && 
            exactMatch.IsActive && 
            (exactMatch.ExpiresAt == null || exactMatch.ExpiresAt > DateTime.UtcNow))
        {
            return new BlocklistResult
            {
                IsBlocked = true,
                Reason = exactMatch.Reason,
                Source = exactMatch.Source,
                Confidence = exactMatch.Confidence,
                Categories = exactMatch.Categories,
                FirstSeen = exactMatch.CreatedAt,
                LastSeen = exactMatch.UpdatedAt
            };
        }

        // Check CIDR ranges
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return new BlocklistResult { IsBlocked = false };

        foreach (var entry in _localBlocklist.Values.Where(e => 
            e.Type == BlocklistEntryType.Range && 
            e.IsActive && 
            (e.ExpiresAt == null || e.ExpiresAt > DateTime.UtcNow)))
        {
            if (IsIPInRange(ip, entry.IPOrRange))
            {
                return new BlocklistResult
                {
                    IsBlocked = true,
                    Reason = entry.Reason,
                    Source = entry.Source,
                    Confidence = entry.Confidence,
                    Categories = entry.Categories,
                    FirstSeen = entry.CreatedAt,
                    LastSeen = entry.UpdatedAt
                };
            }
        }

        return new BlocklistResult { IsBlocked = false };
    }

    private async Task<BlocklistResult> CheckExternalSourceAsync(string ipAddress, BlocklistSource source, CancellationToken cancellationToken)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var url = source.Url.Replace("{ip}", ipAddress);
            var response = await _httpClient.GetStringAsync(url, cancellationToken);
            
            stopwatch.Stop();
            UpdateSourceStatistics(source.Name, true, stopwatch.ElapsedMilliseconds);

            return ParseExternalResponse(response, source);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking external blocklist source {Source} for IP {IP}", source.Name, ipAddress);
            UpdateSourceStatistics(source.Name, false, 0, ex.Message);
            return new BlocklistResult { IsBlocked = false };
        }
    }

    private BlocklistResult ParseExternalResponse(string response, BlocklistSource source)
    {
        try
        {
            switch (source.Format)
            {
                case BlocklistFormat.Json:
                    return ParseJsonResponse(response, source);
                case BlocklistFormat.Text:
                    return ParseTextResponse(response, source);
                case BlocklistFormat.Csv:
                    return ParseCsvResponse(response, source);
                default:
                    return new BlocklistResult { IsBlocked = false };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing response from blocklist source {Source}", source.Name);
            return new BlocklistResult { IsBlocked = false };
        }
    }

    private BlocklistResult ParseJsonResponse(string response, BlocklistSource source)
    {
        var json = JsonDocument.Parse(response);
        var isBlocked = json.RootElement.GetProperty("blocked").GetBoolean();
        
        var result = new BlocklistResult { IsBlocked = isBlocked };
        
        if (isBlocked)
        {
            result.Reason = json.RootElement.TryGetProperty("reason", out var reason) ? reason.GetString() : "External blocklist";
            result.Source = source.Name;
            result.Confidence = json.RootElement.TryGetProperty("confidence", out var confidence) ? confidence.GetDouble() : 100.0;
            
            if (json.RootElement.TryGetProperty("categories", out var categories))
            {
                result.Categories = categories.EnumerateArray().Select(c => c.GetString() ?? "").ToList();
            }
        }
        
        return result;
    }

    private BlocklistResult ParseTextResponse(string response, BlocklistSource source)
    {
        var isBlocked = response.Trim().Equals("true", StringComparison.OrdinalIgnoreCase) ||
                       response.Trim().Equals("1", StringComparison.OrdinalIgnoreCase) ||
                       response.Trim().Equals("blocked", StringComparison.OrdinalIgnoreCase);

        return new BlocklistResult
        {
            IsBlocked = isBlocked,
            Reason = isBlocked ? $"Blocked by {source.Name}" : null,
            Source = isBlocked ? source.Name : null,
            Confidence = isBlocked ? 90.0 : 0.0
        };
    }

    private BlocklistResult ParseCsvResponse(string response, BlocklistSource source)
    {
        var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length > 1) // Skip header
        {
            var data = lines[1].Split(',');
            var isBlocked = data.Length > 0 && data[0].Equals("true", StringComparison.OrdinalIgnoreCase);
            
            return new BlocklistResult
            {
                IsBlocked = isBlocked,
                Reason = isBlocked && data.Length > 1 ? data[1] : null,
                Source = isBlocked ? source.Name : null,
                Confidence = isBlocked && data.Length > 2 && double.TryParse(data[2], out var conf) ? conf : 90.0
            };
        }
        
        return new BlocklistResult { IsBlocked = false };
    }

    private async Task RefreshFromSourceAsync(BlocklistSource source, CancellationToken cancellationToken)
    {
        if (source.Type != BlocklistSourceType.File)
            return;

        try
        {
            var content = source.Url.StartsWith("http") 
                ? await _httpClient.GetStringAsync(source.Url, cancellationToken)
                : await File.ReadAllTextAsync(source.Url, cancellationToken);

            ProcessBlocklistContent(content, source);
            UpdateSourceStatistics(source.Name, true, 0);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing blocklist from source {Source}", source.Name);
            UpdateSourceStatistics(source.Name, false, 0, ex.Message);
        }
    }

    private void ProcessBlocklistContent(string content, BlocklistSource source)
    {
        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.TrimStart().StartsWith('#')) // Skip comments
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrEmpty(line));

        var count = 0;
        foreach (var line in lines)
        {
            if (IPAddress.TryParse(line, out _) || IsValidCIDR(line))
            {
                var entry = new BlocklistEntry
                {
                    IPOrRange = line,
                    Type = line.Contains('/') ? BlocklistEntryType.Range : BlocklistEntryType.IP,
                    Source = source.Name,
                    Reason = $"External blocklist: {source.Name}",
                    Categories = new List<string> { source.Category },
                    Confidence = 90.0
                };

                _localBlocklist[line] = entry;
                count++;
            }
        }

        _logger.LogInformation("Loaded {Count} entries from blocklist source {Source}", count, source.Name);
        _sourceStats[source.Name].EntryCount = count;
    }

    private void UpdateSourceStatistics(string sourceName, bool success, long responseTime, string? error = null)
    {
        if (_sourceStats.TryGetValue(sourceName, out var stats))
        {
            stats.LastUpdate = success ? DateTime.UtcNow : stats.LastUpdate;
            stats.LastError = error;
            stats.AverageResponseTime = (stats.AverageResponseTime + responseTime) / 2;
            
            // Update success rate (simplified calculation)
            stats.SuccessRate = success ? Math.Min(100, stats.SuccessRate + 1) : Math.Max(0, stats.SuccessRate - 1);
        }
    }

    private void CleanupExpiredEntries()
    {
        var expiredKeys = _localBlocklist
            .Where(kvp => kvp.Value.ExpiresAt.HasValue && kvp.Value.ExpiresAt <= DateTime.UtcNow)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            _localBlocklist.TryRemove(key, out _);
        }

        if (expiredKeys.Count > 0)
        {
            _logger.LogInformation("Cleaned up {Count} expired blocklist entries", expiredKeys.Count);
        }
    }

    private static bool IsValidCIDR(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2)
            return false;

        if (!IPAddress.TryParse(parts[0], out var ip))
            return false;

        if (!int.TryParse(parts[1], out var prefix))
            return false;

        var maxPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return prefix >= 0 && prefix <= maxPrefix;
    }

    private static bool IsIPInRange(IPAddress ip, string cidrRange)
    {
        var parts = cidrRange.Split('/');
        if (parts.Length != 2)
            return false;

        if (!IPAddress.TryParse(parts[0], out var networkAddress))
            return false;

        if (!int.TryParse(parts[1], out var prefixLength))
            return false;

        var networkBytes = networkAddress.GetAddressBytes();
        var addressBytes = ip.GetAddressBytes();

        if (networkBytes.Length != addressBytes.Length)
            return false;

        var maskBits = prefixLength;
        for (int i = 0; i < networkBytes.Length; i++)
        {
            var mask = maskBits >= 8 ? 0xFF : maskBits > 0 ? (0xFF << (8 - maskBits)) & 0xFF : 0x00;
            
            if ((networkBytes[i] & mask) != (addressBytes[i] & mask))
                return false;

            maskBits = Math.Max(0, maskBits - 8);
        }

        return true;
    }

    private long GetTodayChecks()
    {
        // This would be implemented with proper metrics collection
        return 0;
    }

    private long GetTodayBlocks()
    {
        // This would be implemented with proper metrics collection
        return 0;
    }

    public void Dispose()
    {
        _refreshTimer?.Dispose();
        _httpClient?.Dispose();
    }
}

/// <summary>
/// Configuration options for the blocklist service
/// </summary>
public class BlocklistOptions
{
    /// <summary>
    /// Whether to enable external blocklist sources
    /// </summary>
    public bool EnableExternalSources { get; set; } = true;

    /// <summary>
    /// How often to refresh blocklists
    /// </summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// How long to cache blocklist results
    /// </summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// HTTP timeout for external sources
    /// </summary>
    public int HttpTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Blocklist sources configuration
    /// </summary>
    public List<BlocklistSource> Sources { get; set; } = new();
}

/// <summary>
/// Configuration for a blocklist source
/// </summary>
public class BlocklistSource
{
    /// <summary>
    /// Source name
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Source type
    /// </summary>
    public BlocklistSourceType Type { get; set; }

    /// <summary>
    /// URL or file path
    /// </summary>
    public string Url { get; set; } = "";

    /// <summary>
    /// Response format
    /// </summary>
    public BlocklistFormat Format { get; set; }

    /// <summary>
    /// Category for entries from this source
    /// </summary>
    public string Category { get; set; } = "General";

    /// <summary>
    /// Whether this source is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;
}

/// <summary>
/// Type of blocklist source
/// </summary>
public enum BlocklistSourceType
{
    /// <summary>
    /// Local file or HTTP download
    /// </summary>
    File,

    /// <summary>
    /// External API for individual IP checks
    /// </summary>
    External
}

/// <summary>
/// Format of blocklist data
/// </summary>
public enum BlocklistFormat
{
    /// <summary>
    /// JSON format
    /// </summary>
    Json,

    /// <summary>
    /// Plain text format
    /// </summary>
    Text,

    /// <summary>
    /// CSV format
    /// </summary>
    Csv
}