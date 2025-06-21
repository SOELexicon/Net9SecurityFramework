using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityFramework.Core.Abstractions;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecurityFramework.Services;

/// <summary>
/// Service for sending security notifications and alerts
/// </summary>
public class NotificationService : INotificationService
{
    private readonly ILogger<NotificationService> _logger;
    private readonly NotificationOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ConcurrentDictionary<string, NotificationSubscription> _subscriptions;
    private readonly ConcurrentDictionary<string, DateTime> _lastNotificationSent;
    private readonly ConcurrentQueue<SecurityAlert> _alertQueue;
    private readonly Timer _processingTimer;
    private readonly NotificationStatistics _statistics;

    public NotificationService(
        ILogger<NotificationService> logger,
        IOptions<NotificationOptions> options,
        HttpClient httpClient)
    {
        _logger = logger;
        _options = options.Value;
        _httpClient = httpClient;
        _subscriptions = new ConcurrentDictionary<string, NotificationSubscription>();
        _lastNotificationSent = new ConcurrentDictionary<string, DateTime>();
        _alertQueue = new ConcurrentQueue<SecurityAlert>();
        _statistics = new NotificationStatistics();

        // Setup HTTP client
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.HttpTimeoutSeconds);

        // Setup background processing timer
        _processingTimer = new Timer(ProcessAlertQueue, null, 
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
    }

    public async Task SendAlertAsync(SecurityAlert alert, CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            _logger.LogDebug("Notification service is disabled, skipping alert {AlertId}", alert.Id);
            return;
        }

        _logger.LogInformation("Processing security alert {AlertId} with severity {Severity}", 
            alert.Id, alert.Severity);

        var matchingSubscriptions = GetMatchingSubscriptions(alert);
        var notificationTasks = new List<Task>();

        foreach (var subscription in matchingSubscriptions)
        {
            if (ShouldSendNotification(alert, subscription))
            {
                notificationTasks.Add(SendNotificationAsync(alert, subscription, cancellationToken));
            }
        }

        if (notificationTasks.Any())
        {
            await Task.WhenAll(notificationTasks);
            _statistics.TotalSent += notificationTasks.Count;
        }
        else
        {
            _logger.LogDebug("No matching subscriptions found for alert {AlertId}", alert.Id);
        }
    }

    public async Task SendBatchAlertsAsync(IEnumerable<SecurityAlert> alerts, CancellationToken cancellationToken = default)
    {
        var alertList = alerts.ToList();
        _logger.LogInformation("Processing batch of {Count} security alerts", alertList.Count);

        var tasks = alertList.Select(alert => SendAlertAsync(alert, cancellationToken));
        await Task.WhenAll(tasks);
    }

    public async Task SubscribeAsync(NotificationSubscription subscription, CancellationToken cancellationToken = default)
    {
        _subscriptions.AddOrUpdate(subscription.Id, subscription, (key, existing) => subscription);
        
        _logger.LogInformation("Added notification subscription {SubscriptionId} for {SubscriberId}", 
            subscription.Id, subscription.SubscriberId);

        // Test the subscription if enabled
        if (_options.TestSubscriptionsOnCreate)
        {
            var testResult = await TestDeliveryAsync(
                subscription.Channel.Type, 
                GetRecipientFromChannel(subscription.Channel), 
                cancellationToken);

            if (!testResult.Success)
            {
                _logger.LogWarning("Test notification failed for subscription {SubscriptionId}: {Error}", 
                    subscription.Id, testResult.ErrorMessage);
            }
        }
    }

    public async Task UnsubscribeAsync(string subscriptionId, CancellationToken cancellationToken = default)
    {
        if (_subscriptions.TryRemove(subscriptionId, out var subscription))
        {
            _logger.LogInformation("Removed notification subscription {SubscriptionId}", subscriptionId);
        }
        else
        {
            _logger.LogWarning("Attempted to remove non-existent subscription {SubscriptionId}", subscriptionId);
        }
    }

    public async Task<IEnumerable<NotificationSubscription>> GetSubscriptionsAsync(CancellationToken cancellationToken = default)
    {
        return _subscriptions.Values.Where(s => s.IsActive);
    }

    public async Task<NotificationTestResult> TestDeliveryAsync(NotificationChannelType channelType, string recipient, CancellationToken cancellationToken = default)
    {
        var testAlert = new SecurityAlert
        {
            Id = "test-" + Guid.NewGuid().ToString("N")[..8],
            Severity = AlertSeverity.Low,
            Category = AlertCategory.SystemHealth,
            Title = "Test Notification",
            Message = "This is a test notification to verify delivery configuration.",
            Timestamp = DateTime.UtcNow
        };

        var testChannel = new NotificationChannel
        {
            Type = channelType,
            Configuration = new Dictionary<string, string> { ["recipient"] = recipient }
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            await DeliverNotificationAsync(testAlert, testChannel, cancellationToken);
            stopwatch.Stop();

            return new NotificationTestResult
            {
                Success = true,
                DeliveryTime = stopwatch.Elapsed
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            
            return new NotificationTestResult
            {
                Success = false,
                DeliveryTime = stopwatch.Elapsed,
                ErrorMessage = ex.Message
            };
        }
    }

    public async Task<NotificationStatistics> GetStatisticsAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default)
    {
        // In a real implementation, this would query from persistent storage
        // For now, return the in-memory statistics
        var stats = new NotificationStatistics
        {
            TimePeriod = timeWindow ?? TimeSpan.FromDays(1),
            TotalSent = _statistics.TotalSent,
            SuccessfulDeliveries = _statistics.SuccessfulDeliveries,
            FailedDeliveries = _statistics.FailedDeliveries,
            AverageDeliveryTime = _statistics.AverageDeliveryTime,
            ChannelStatistics = _statistics.ChannelStatistics,
            SeverityStatistics = _statistics.SeverityStatistics,
            RecentFailures = _statistics.RecentFailures.TakeLast(10).ToList()
        };

        return stats;
    }

    public async Task ProcessSecurityEventAsync(SecurityAnalyticsEvent securityEvent, CancellationToken cancellationToken = default)
    {
        // Convert security event to alert if it meets criteria
        var alert = ConvertEventToAlert(securityEvent);
        if (alert != null)
        {
            if (_options.UseAsyncProcessing)
            {
                _alertQueue.Enqueue(alert);
            }
            else
            {
                await SendAlertAsync(alert, cancellationToken);
            }
        }
    }

    public async Task UpdatePreferencesAsync(string subscriberId, NotificationPreferences preferences, CancellationToken cancellationToken = default)
    {
        var subscriptionsToUpdate = _subscriptions.Values
            .Where(s => s.SubscriberId == subscriberId)
            .ToList();

        foreach (var subscription in subscriptionsToUpdate)
        {
            subscription.Preferences = preferences;
            _subscriptions.TryUpdate(subscription.Id, subscription, subscription);
        }

        _logger.LogInformation("Updated notification preferences for subscriber {SubscriberId}", subscriberId);
    }

    // Private helper methods

    private List<NotificationSubscription> GetMatchingSubscriptions(SecurityAlert alert)
    {
        return _subscriptions.Values
            .Where(s => s.IsActive && MatchesFilter(alert, s.Filter))
            .OrderBy(s => s.Channel.Priority)
            .ToList();
    }

    private bool MatchesFilter(SecurityAlert alert, NotificationFilter filter)
    {
        // Severity check
        if (alert.Severity < filter.MinimumSeverity)
            return false;

        // Threat score check
        if (alert.ThreatScore < filter.MinimumThreatScore)
            return false;

        // Category checks
        if (filter.IncludeCategories.Any() && !filter.IncludeCategories.Contains(alert.Category))
            return false;

        if (filter.ExcludeCategories.Contains(alert.Category))
            return false;

        // IP pattern checks
        if (!string.IsNullOrEmpty(alert.SourceIP))
        {
            if (filter.IncludeIPPatterns.Any() && 
                !filter.IncludeIPPatterns.Any(pattern => Regex.IsMatch(alert.SourceIP, pattern)))
                return false;

            if (filter.ExcludeIPPatterns.Any(pattern => Regex.IsMatch(alert.SourceIP, pattern)))
                return false;
        }

        // Resource pattern checks
        if (!string.IsNullOrEmpty(alert.AffectedResource))
        {
            if (filter.IncludeResourcePatterns.Any() && 
                !filter.IncludeResourcePatterns.Any(pattern => Regex.IsMatch(alert.AffectedResource, pattern)))
                return false;

            if (filter.ExcludeResourcePatterns.Any(pattern => Regex.IsMatch(alert.AffectedResource, pattern)))
                return false;
        }

        // Tag checks
        if (filter.RequiredTags.Any() && !filter.RequiredTags.All(tag => alert.Tags.Contains(tag)))
            return false;

        if (filter.ExcludedTags.Any(tag => alert.Tags.Contains(tag)))
            return false;

        // Time window check
        if (filter.TimeWindow != null && !IsWithinTimeWindow(alert.Timestamp, filter.TimeWindow))
            return false;

        return true;
    }

    private bool ShouldSendNotification(SecurityAlert alert, NotificationSubscription subscription)
    {
        var key = $"{subscription.Id}_{alert.Id}";

        // Rate limiting check
        if (subscription.Preferences.MaxNotificationsPerHour > 0)
        {
            var hourAgo = DateTime.UtcNow.AddHours(-1);
            var recentNotifications = _lastNotificationSent.Values.Count(t => t >= hourAgo);
            
            if (recentNotifications >= subscription.Preferences.MaxNotificationsPerHour)
            {
                _logger.LogDebug("Rate limit exceeded for subscription {SubscriptionId}", subscription.Id);
                return false;
            }
        }

        // Quiet hours check
        if (subscription.Preferences.QuietHours != null && 
            IsInQuietHours(DateTime.UtcNow, subscription.Preferences.QuietHours) &&
            (subscription.Preferences.QuietHours.RespectForCritical || alert.Severity != AlertSeverity.Critical))
        {
            _logger.LogDebug("Suppressing notification due to quiet hours for subscription {SubscriptionId}", subscription.Id);
            return false;
        }

        // Deduplication check
        if (subscription.Preferences.EnableDeduplication)
        {
            var cutoff = DateTime.UtcNow - subscription.Preferences.DeduplicationWindow;
            var recentSimilarAlert = _lastNotificationSent.Keys
                .Where(k => k.StartsWith(subscription.Id) && 
                           _lastNotificationSent.TryGetValue(k, out var time) && time >= cutoff)
                .Any(k => IsSimilarAlert(k, alert));

            if (recentSimilarAlert)
            {
                _logger.LogDebug("Suppressing duplicate alert for subscription {SubscriptionId}", subscription.Id);
                return false;
            }
        }

        return true;
    }

    private async Task SendNotificationAsync(SecurityAlert alert, NotificationSubscription subscription, CancellationToken cancellationToken)
    {
        try
        {
            await DeliverNotificationAsync(alert, subscription.Channel, cancellationToken);
            
            // Record successful delivery
            var key = $"{subscription.Id}_{alert.Id}";
            _lastNotificationSent[key] = DateTime.UtcNow;
            subscription.LastNotificationSent = DateTime.UtcNow;
            
            _statistics.SuccessfulDeliveries++;
            
            _logger.LogInformation("Successfully sent alert {AlertId} to subscription {SubscriptionId}", 
                alert.Id, subscription.Id);
        }
        catch (Exception ex)
        {
            _statistics.FailedDeliveries++;
            _statistics.RecentFailures.Add(new DeliveryFailure
            {
                Timestamp = DateTime.UtcNow,
                ChannelType = subscription.Channel.Type,
                Recipient = GetRecipientFromChannel(subscription.Channel),
                ErrorMessage = ex.Message,
                AlertId = alert.Id
            });

            _logger.LogError(ex, "Failed to send alert {AlertId} to subscription {SubscriptionId}", 
                alert.Id, subscription.Id);
        }
    }

    private async Task DeliverNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        if (!channel.IsEnabled)
        {
            _logger.LogDebug("Channel {ChannelType} is disabled, skipping notification", channel.Type);
            return;
        }

        switch (channel.Type)
        {
            case NotificationChannelType.Email:
                await SendEmailNotificationAsync(alert, channel, cancellationToken);
                break;
            case NotificationChannelType.Webhook:
                await SendWebhookNotificationAsync(alert, channel, cancellationToken);
                break;
            case NotificationChannelType.Slack:
                await SendSlackNotificationAsync(alert, channel, cancellationToken);
                break;
            case NotificationChannelType.Teams:
                await SendTeamsNotificationAsync(alert, channel, cancellationToken);
                break;
            case NotificationChannelType.Discord:
                await SendDiscordNotificationAsync(alert, channel, cancellationToken);
                break;
            case NotificationChannelType.SMS:
                await SendSMSNotificationAsync(alert, channel, cancellationToken);
                break;
            default:
                _logger.LogWarning("Unsupported notification channel type: {ChannelType}", channel.Type);
                break;
        }
    }

    private async Task SendEmailNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        // This is a placeholder - in production you'd integrate with an email service
        _logger.LogInformation("Sending email notification for alert {AlertId} to {Recipient}", 
            alert.Id, channel.Configuration.GetValueOrDefault("recipient", "unknown"));
        
        await Task.Delay(100, cancellationToken); // Simulate email sending
    }

    private async Task SendWebhookNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        var webhookUrl = channel.Configuration.GetValueOrDefault("url");
        if (string.IsNullOrEmpty(webhookUrl))
        {
            throw new InvalidOperationException("Webhook URL is required");
        }

        var payload = new
        {
            alert_id = alert.Id,
            timestamp = alert.Timestamp,
            severity = alert.Severity.ToString(),
            category = alert.Category.ToString(),
            title = alert.Title,
            message = alert.Message,
            source_ip = alert.SourceIP,
            affected_resource = alert.AffectedResource,
            threat_score = alert.ThreatScore,
            recommended_actions = alert.RecommendedActions,
            context = alert.Context,
            tags = alert.Tags
        };

        var response = await _httpClient.PostAsJsonAsync(webhookUrl, payload, cancellationToken);
        response.EnsureSuccessStatusCode();

        _logger.LogInformation("Sent webhook notification for alert {AlertId} to {Url}", alert.Id, webhookUrl);
    }

    private async Task SendSlackNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        var webhookUrl = channel.Configuration.GetValueOrDefault("webhook_url");
        if (string.IsNullOrEmpty(webhookUrl))
        {
            throw new InvalidOperationException("Slack webhook URL is required");
        }

        var color = alert.Severity switch
        {
            AlertSeverity.Critical => "danger",
            AlertSeverity.High => "warning",
            AlertSeverity.Medium => "good",
            _ => "#439FE0"
        };

        var payload = new
        {
            text = $"Security Alert: {alert.Title}",
            attachments = new[]
            {
                new
                {
                    color = color,
                    fields = new[]
                    {
                        new { title = "Severity", value = alert.Severity.ToString(), @short = true },
                        new { title = "Category", value = alert.Category.ToString(), @short = true },
                        new { title = "Source IP", value = alert.SourceIP ?? "N/A", @short = true },
                        new { title = "Threat Score", value = alert.ThreatScore.ToString("F1"), @short = true },
                        new { title = "Message", value = alert.Message, @short = false }
                    },
                    footer = "Security Framework",
                    ts = ((DateTimeOffset)alert.Timestamp).ToUnixTimeSeconds()
                }
            }
        };

        var response = await _httpClient.PostAsJsonAsync(webhookUrl, payload, cancellationToken);
        response.EnsureSuccessStatusCode();

        _logger.LogInformation("Sent Slack notification for alert {AlertId}", alert.Id);
    }

    private async Task SendTeamsNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        var webhookUrl = channel.Configuration.GetValueOrDefault("webhook_url");
        if (string.IsNullOrEmpty(webhookUrl))
        {
            throw new InvalidOperationException("Teams webhook URL is required");
        }

        var themeColor = alert.Severity switch
        {
            AlertSeverity.Critical => "FF0000",
            AlertSeverity.High => "FF8C00",
            AlertSeverity.Medium => "FFD700",
            _ => "0078D4"
        };

        var payload = new
        {
            @type = "MessageCard",
            @context = "http://schema.org/extensions",
            themeColor = themeColor,
            summary = $"Security Alert: {alert.Title}",
            sections = new[]
            {
                new
                {
                    activityTitle = alert.Title,
                    activitySubtitle = $"Severity: {alert.Severity} | Category: {alert.Category}",
                    facts = new[]
                    {
                        new { name = "Source IP", value = alert.SourceIP ?? "N/A" },
                        new { name = "Threat Score", value = alert.ThreatScore.ToString("F1") },
                        new { name = "Timestamp", value = alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss UTC") }
                    },
                    text = alert.Message
                }
            }
        };

        var response = await _httpClient.PostAsJsonAsync(webhookUrl, payload, cancellationToken);
        response.EnsureSuccessStatusCode();

        _logger.LogInformation("Sent Teams notification for alert {AlertId}", alert.Id);
    }

    private async Task SendDiscordNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        var webhookUrl = channel.Configuration.GetValueOrDefault("webhook_url");
        if (string.IsNullOrEmpty(webhookUrl))
        {
            throw new InvalidOperationException("Discord webhook URL is required");
        }

        var color = alert.Severity switch
        {
            AlertSeverity.Critical => 16711680, // Red
            AlertSeverity.High => 16753920,    // Orange
            AlertSeverity.Medium => 16776960,  // Yellow
            _ => 4886754                       // Blue
        };

        var payload = new
        {
            embeds = new[]
            {
                new
                {
                    title = alert.Title,
                    description = alert.Message,
                    color = color,
                    fields = new[]
                    {
                        new { name = "Severity", value = alert.Severity.ToString(), inline = true },
                        new { name = "Category", value = alert.Category.ToString(), inline = true },
                        new { name = "Source IP", value = alert.SourceIP ?? "N/A", inline = true },
                        new { name = "Threat Score", value = alert.ThreatScore.ToString("F1"), inline = true }
                    },
                    footer = new { text = "Security Framework" },
                    timestamp = alert.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
            }
        };

        var response = await _httpClient.PostAsJsonAsync(webhookUrl, payload, cancellationToken);
        response.EnsureSuccessStatusCode();

        _logger.LogInformation("Sent Discord notification for alert {AlertId}", alert.Id);
    }

    private async Task SendSMSNotificationAsync(SecurityAlert alert, NotificationChannel channel, CancellationToken cancellationToken)
    {
        // This is a placeholder - in production you'd integrate with an SMS service like Twilio
        var phoneNumber = channel.Configuration.GetValueOrDefault("phone_number");
        var message = $"Security Alert: {alert.Title} (Severity: {alert.Severity})";

        _logger.LogInformation("Sending SMS notification for alert {AlertId} to {PhoneNumber}", 
            alert.Id, phoneNumber);
        
        await Task.Delay(100, cancellationToken); // Simulate SMS sending
    }

    private SecurityAlert? ConvertEventToAlert(SecurityAnalyticsEvent securityEvent)
    {
        // Convert security event to alert based on configured thresholds
        if (securityEvent.ThreatScore < _options.MinimumThreatScoreForAlert)
            return null;

        var severity = securityEvent.Severity switch
        {
            SecurityEventSeverity.Critical => AlertSeverity.Critical,
            SecurityEventSeverity.High => AlertSeverity.High,
            SecurityEventSeverity.Medium => AlertSeverity.Medium,
            _ => AlertSeverity.Low
        };

        var category = securityEvent.Type switch
        {
            SecurityEventType.ThreatDetected => AlertCategory.ThreatDetection,
            SecurityEventType.RequestBlocked => AlertCategory.RequestBlocked,
            SecurityEventType.ParameterViolation => AlertCategory.ParameterViolation,
            SecurityEventType.AnomalyDetected => AlertCategory.AnomalyDetected,
            _ => AlertCategory.ThreatDetection
        };

        return new SecurityAlert
        {
            Id = securityEvent.Id,
            Timestamp = securityEvent.Timestamp,
            Severity = severity,
            Category = category,
            Title = $"Security Event: {securityEvent.Type}",
            Message = securityEvent.Description,
            SourceIP = securityEvent.IPAddress,
            AffectedResource = securityEvent.RequestPath,
            ThreatScore = securityEvent.ThreatScore,
            Tags = securityEvent.Categories,
            Context = securityEvent.Metadata,
            RequiresImmediateAttention = severity >= AlertSeverity.High
        };
    }

    private void ProcessAlertQueue(object? state)
    {
        var processedCount = 0;
        var maxBatchSize = _options.ProcessingBatchSize;

        while (_alertQueue.TryDequeue(out var alert) && processedCount < maxBatchSize)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await SendAlertAsync(alert, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing queued alert {AlertId}", alert.Id);
                }
            });

            processedCount++;
        }

        if (processedCount > 0)
        {
            _logger.LogDebug("Processed {Count} alerts from queue", processedCount);
        }
    }

    private static string GetRecipientFromChannel(NotificationChannel channel)
    {
        return channel.Configuration.GetValueOrDefault("recipient") ??
               channel.Configuration.GetValueOrDefault("email") ??
               channel.Configuration.GetValueOrDefault("phone_number") ??
               channel.Configuration.GetValueOrDefault("url") ??
               "unknown";
    }

    private static bool IsWithinTimeWindow(DateTime timestamp, TimeWindowFilter timeWindow)
    {
        var timeZone = TimeZoneInfo.FindSystemTimeZoneById(timeWindow.TimeZone);
        var localTime = TimeZoneInfo.ConvertTime(timestamp, timeZone);
        
        if (!timeWindow.DaysOfWeek.Contains(localTime.DayOfWeek))
            return false;

        var currentTime = TimeOnly.FromDateTime(localTime);
        return currentTime >= timeWindow.StartTime && currentTime <= timeWindow.EndTime;
    }

    private static bool IsInQuietHours(DateTime timestamp, QuietHours quietHours)
    {
        var timeZone = TimeZoneInfo.FindSystemTimeZoneById(quietHours.TimeZone);
        var localTime = TimeZoneInfo.ConvertTime(timestamp, timeZone);
        var currentTime = TimeOnly.FromDateTime(localTime);
        
        // Handle quiet hours that span midnight
        if (quietHours.StartTime > quietHours.EndTime)
        {
            return currentTime >= quietHours.StartTime || currentTime <= quietHours.EndTime;
        }
        else
        {
            return currentTime >= quietHours.StartTime && currentTime <= quietHours.EndTime;
        }
    }

    private static bool IsSimilarAlert(string key, SecurityAlert alert)
    {
        // Simplified similarity check - in production this would be more sophisticated
        return key.Contains(alert.Category.ToString()) && key.Contains(alert.SourceIP ?? "");
    }

    public void Dispose()
    {
        _processingTimer?.Dispose();
        _httpClient?.Dispose();
    }
}

/// <summary>
/// Configuration options for the notification service
/// </summary>
public class NotificationOptions
{
    /// <summary>
    /// Whether notifications are enabled
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether to use asynchronous processing for alerts
    /// </summary>
    public bool UseAsyncProcessing { get; set; } = true;

    /// <summary>
    /// Batch size for processing alerts
    /// </summary>
    public int ProcessingBatchSize { get; set; } = 50;

    /// <summary>
    /// HTTP timeout for webhook deliveries
    /// </summary>
    public int HttpTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Minimum threat score to generate alerts
    /// </summary>
    public double MinimumThreatScoreForAlert { get; set; } = 70.0;

    /// <summary>
    /// Whether to test subscriptions when they are created
    /// </summary>
    public bool TestSubscriptionsOnCreate { get; set; } = true;

    /// <summary>
    /// Maximum number of recent failures to track
    /// </summary>
    public int MaxRecentFailures { get; set; } = 100;

    /// <summary>
    /// Default notification preferences for new subscriptions
    /// </summary>
    public NotificationPreferences DefaultPreferences { get; set; } = new();
}