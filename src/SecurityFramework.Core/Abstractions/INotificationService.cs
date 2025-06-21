namespace SecurityFramework.Core.Abstractions;

/// <summary>
/// Service for sending security notifications and alerts
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// Sends a security alert
    /// </summary>
    /// <param name="alert">Security alert to send</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task SendAlertAsync(SecurityAlert alert, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends multiple alerts in batch
    /// </summary>
    /// <param name="alerts">Collection of security alerts</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task SendBatchAlertsAsync(IEnumerable<SecurityAlert> alerts, CancellationToken cancellationToken = default);

    /// <summary>
    /// Subscribes to security event notifications
    /// </summary>
    /// <param name="subscription">Notification subscription details</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task SubscribeAsync(NotificationSubscription subscription, CancellationToken cancellationToken = default);

    /// <summary>
    /// Unsubscribes from security event notifications
    /// </summary>
    /// <param name="subscriptionId">Subscription ID to remove</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task UnsubscribeAsync(string subscriptionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all active subscriptions
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Collection of active subscriptions</returns>
    Task<IEnumerable<NotificationSubscription>> GetSubscriptionsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Tests notification delivery for a specific channel
    /// </summary>
    /// <param name="channelType">Type of notification channel</param>
    /// <param name="recipient">Recipient address/identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Test result</returns>
    Task<NotificationTestResult> TestDeliveryAsync(NotificationChannelType channelType, string recipient, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets notification delivery statistics
    /// </summary>
    /// <param name="timeWindow">Time window for statistics</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Delivery statistics</returns>
    Task<NotificationStatistics> GetStatisticsAsync(TimeSpan? timeWindow = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Processes a security event and determines if notifications should be sent
    /// </summary>
    /// <param name="securityEvent">Security event to process</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task ProcessSecurityEventAsync(SecurityAnalyticsEvent securityEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates notification preferences for a subscriber
    /// </summary>
    /// <param name="subscriberId">Subscriber identifier</param>
    /// <param name="preferences">Updated notification preferences</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the operation</returns>
    Task UpdatePreferencesAsync(string subscriberId, NotificationPreferences preferences, CancellationToken cancellationToken = default);
}

/// <summary>
/// Security alert information
/// </summary>
public class SecurityAlert
{
    /// <summary>
    /// Alert unique identifier
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Alert timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Alert severity level
    /// </summary>
    public AlertSeverity Severity { get; set; }

    /// <summary>
    /// Alert category
    /// </summary>
    public AlertCategory Category { get; set; }

    /// <summary>
    /// Alert title/subject
    /// </summary>
    public string Title { get; set; } = "";

    /// <summary>
    /// Detailed alert message
    /// </summary>
    public string Message { get; set; } = "";

    /// <summary>
    /// Source IP address (if applicable)
    /// </summary>
    public string? SourceIP { get; set; }

    /// <summary>
    /// Affected resource or endpoint
    /// </summary>
    public string? AffectedResource { get; set; }

    /// <summary>
    /// Threat score associated with this alert
    /// </summary>
    public double ThreatScore { get; set; }

    /// <summary>
    /// Recommended actions
    /// </summary>
    public List<string> RecommendedActions { get; set; } = new();

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> Context { get; set; } = new();

    /// <summary>
    /// Alert tags for categorization
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// Whether this alert requires immediate attention
    /// </summary>
    public bool RequiresImmediateAttention { get; set; }

    /// <summary>
    /// Alert expiration time (if applicable)
    /// </summary>
    public DateTime? ExpiresAt { get; set; }
}

/// <summary>
/// Notification subscription configuration
/// </summary>
public class NotificationSubscription
{
    /// <summary>
    /// Subscription unique identifier
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Subscriber identifier (user ID, team name, etc.)
    /// </summary>
    public string SubscriberId { get; set; } = "";

    /// <summary>
    /// Subscription name/description
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Notification channel configuration
    /// </summary>
    public NotificationChannel Channel { get; set; } = new();

    /// <summary>
    /// Filters for determining which alerts to send
    /// </summary>
    public NotificationFilter Filter { get; set; } = new();

    /// <summary>
    /// Notification preferences
    /// </summary>
    public NotificationPreferences Preferences { get; set; } = new();

    /// <summary>
    /// Whether this subscription is active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Subscription creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Last notification sent timestamp
    /// </summary>
    public DateTime? LastNotificationSent { get; set; }
}

/// <summary>
/// Notification channel configuration
/// </summary>
public class NotificationChannel
{
    /// <summary>
    /// Channel type
    /// </summary>
    public NotificationChannelType Type { get; set; }

    /// <summary>
    /// Channel-specific configuration
    /// </summary>
    public Dictionary<string, string> Configuration { get; set; } = new();

    /// <summary>
    /// Whether this channel is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Priority for this channel (higher = more priority)
    /// </summary>
    public int Priority { get; set; } = 1;

    /// <summary>
    /// Rate limiting configuration
    /// </summary>
    public ChannelRateLimit? RateLimit { get; set; }
}

/// <summary>
/// Notification filter criteria
/// </summary>
public class NotificationFilter
{
    /// <summary>
    /// Minimum severity level to trigger notifications
    /// </summary>
    public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.Medium;

    /// <summary>
    /// Alert categories to include
    /// </summary>
    public List<AlertCategory> IncludeCategories { get; set; } = new();

    /// <summary>
    /// Alert categories to exclude
    /// </summary>
    public List<AlertCategory> ExcludeCategories { get; set; } = new();

    /// <summary>
    /// Minimum threat score to trigger notifications
    /// </summary>
    public double MinimumThreatScore { get; set; } = 50.0;

    /// <summary>
    /// IP address patterns to include (regex)
    /// </summary>
    public List<string> IncludeIPPatterns { get; set; } = new();

    /// <summary>
    /// IP address patterns to exclude (regex)
    /// </summary>
    public List<string> ExcludeIPPatterns { get; set; } = new();

    /// <summary>
    /// Resource patterns to include (regex)
    /// </summary>
    public List<string> IncludeResourcePatterns { get; set; } = new();

    /// <summary>
    /// Resource patterns to exclude (regex)
    /// </summary>
    public List<string> ExcludeResourcePatterns { get; set; } = new();

    /// <summary>
    /// Tags that must be present
    /// </summary>
    public List<string> RequiredTags { get; set; } = new();

    /// <summary>
    /// Tags that must not be present
    /// </summary>
    public List<string> ExcludedTags { get; set; } = new();

    /// <summary>
    /// Time window filters
    /// </summary>
    public TimeWindowFilter? TimeWindow { get; set; }
}

/// <summary>
/// Notification preferences
/// </summary>
public class NotificationPreferences
{
    /// <summary>
    /// Whether to enable digest notifications
    /// </summary>
    public bool EnableDigest { get; set; } = false;

    /// <summary>
    /// Digest frequency
    /// </summary>
    public DigestFrequency DigestFrequency { get; set; } = DigestFrequency.Daily;

    /// <summary>
    /// Maximum notifications per hour
    /// </summary>
    public int MaxNotificationsPerHour { get; set; } = 10;

    /// <summary>
    /// Quiet hours configuration
    /// </summary>
    public QuietHours? QuietHours { get; set; }

    /// <summary>
    /// Whether to include context data in notifications
    /// </summary>
    public bool IncludeContext { get; set; } = true;

    /// <summary>
    /// Whether to include recommended actions
    /// </summary>
    public bool IncludeRecommendedActions { get; set; } = true;

    /// <summary>
    /// Message format preference
    /// </summary>
    public MessageFormat MessageFormat { get; set; } = MessageFormat.Rich;

    /// <summary>
    /// Whether to deduplicate similar alerts
    /// </summary>
    public bool EnableDeduplication { get; set; } = true;

    /// <summary>
    /// Deduplication time window
    /// </summary>
    public TimeSpan DeduplicationWindow { get; set; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// Test result for notification delivery
/// </summary>
public class NotificationTestResult
{
    /// <summary>
    /// Whether the test was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Test execution timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Time taken to deliver the test notification
    /// </summary>
    public TimeSpan DeliveryTime { get; set; }

    /// <summary>
    /// Error message (if any)
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Response details from the notification provider
    /// </summary>
    public Dictionary<string, object> ProviderResponse { get; set; } = new();
}

/// <summary>
/// Notification delivery statistics
/// </summary>
public class NotificationStatistics
{
    /// <summary>
    /// Time period for these statistics
    /// </summary>
    public TimeSpan TimePeriod { get; set; }

    /// <summary>
    /// Total notifications sent
    /// </summary>
    public long TotalSent { get; set; }

    /// <summary>
    /// Successful deliveries
    /// </summary>
    public long SuccessfulDeliveries { get; set; }

    /// <summary>
    /// Failed deliveries
    /// </summary>
    public long FailedDeliveries { get; set; }

    /// <summary>
    /// Average delivery time
    /// </summary>
    public TimeSpan AverageDeliveryTime { get; set; }

    /// <summary>
    /// Statistics by channel type
    /// </summary>
    public Dictionary<NotificationChannelType, ChannelStatistics> ChannelStatistics { get; set; } = new();

    /// <summary>
    /// Statistics by severity level
    /// </summary>
    public Dictionary<AlertSeverity, long> SeverityStatistics { get; set; } = new();

    /// <summary>
    /// Recent delivery failures
    /// </summary>
    public List<DeliveryFailure> RecentFailures { get; set; } = new();
}

// Supporting classes and enums

/// <summary>
/// Alert severity levels
/// </summary>
public enum AlertSeverity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

/// <summary>
/// Alert categories
/// </summary>
public enum AlertCategory
{
    ThreatDetection,
    RequestBlocked,
    ParameterViolation,
    AnomalyDetected,
    SystemHealth,
    Configuration,
    Performance,
    Compliance
}

/// <summary>
/// Notification channel types
/// </summary>
public enum NotificationChannelType
{
    Email,
    SMS,
    Webhook,
    Slack,
    Teams,
    Discord,
    PagerDuty,
    SignalR,
    WebSocket
}

/// <summary>
/// Digest frequency options
/// </summary>
public enum DigestFrequency
{
    Hourly,
    Daily,
    Weekly
}

/// <summary>
/// Message format options
/// </summary>
public enum MessageFormat
{
    Plain,
    Rich,
    Json
}

/// <summary>
/// Channel rate limiting configuration
/// </summary>
public class ChannelRateLimit
{
    /// <summary>
    /// Maximum messages per time window
    /// </summary>
    public int MaxMessages { get; set; } = 10;

    /// <summary>
    /// Time window for rate limiting
    /// </summary>
    public TimeSpan TimeWindow { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Whether to queue messages when rate limit is exceeded
    /// </summary>
    public bool QueueOnExceeded { get; set; } = true;
}

/// <summary>
/// Time window filter for notifications
/// </summary>
public class TimeWindowFilter
{
    /// <summary>
    /// Start time (24-hour format)
    /// </summary>
    public TimeOnly StartTime { get; set; } = new(0, 0);

    /// <summary>
    /// End time (24-hour format)
    /// </summary>
    public TimeOnly EndTime { get; set; } = new(23, 59);

    /// <summary>
    /// Days of week to include
    /// </summary>
    public List<DayOfWeek> DaysOfWeek { get; set; } = new() { 
        DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, 
        DayOfWeek.Thursday, DayOfWeek.Friday 
    };

    /// <summary>
    /// Time zone for the time window
    /// </summary>
    public string TimeZone { get; set; } = "UTC";
}

/// <summary>
/// Quiet hours configuration
/// </summary>
public class QuietHours
{
    /// <summary>
    /// Start time for quiet hours
    /// </summary>
    public TimeOnly StartTime { get; set; } = new(22, 0);

    /// <summary>
    /// End time for quiet hours
    /// </summary>
    public TimeOnly EndTime { get; set; } = new(8, 0);

    /// <summary>
    /// Whether to respect quiet hours for critical alerts
    /// </summary>
    public bool RespectForCritical { get; set; } = false;

    /// <summary>
    /// Time zone for quiet hours
    /// </summary>
    public string TimeZone { get; set; } = "UTC";
}

/// <summary>
/// Channel-specific delivery statistics
/// </summary>
public class ChannelStatistics
{
    /// <summary>
    /// Total messages sent via this channel
    /// </summary>
    public long TotalSent { get; set; }

    /// <summary>
    /// Successful deliveries
    /// </summary>
    public long Successful { get; set; }

    /// <summary>
    /// Failed deliveries
    /// </summary>
    public long Failed { get; set; }

    /// <summary>
    /// Average delivery time for this channel
    /// </summary>
    public TimeSpan AverageDeliveryTime { get; set; }

    /// <summary>
    /// Success rate percentage
    /// </summary>
    public double SuccessRate => TotalSent > 0 ? (double)Successful / TotalSent * 100 : 0;
}

/// <summary>
/// Delivery failure information
/// </summary>
public class DeliveryFailure
{
    /// <summary>
    /// Failure timestamp
    /// </summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// Channel type that failed
    /// </summary>
    public NotificationChannelType ChannelType { get; set; }

    /// <summary>
    /// Recipient identifier
    /// </summary>
    public string Recipient { get; set; } = "";

    /// <summary>
    /// Error message
    /// </summary>
    public string ErrorMessage { get; set; } = "";

    /// <summary>
    /// Alert that failed to deliver
    /// </summary>
    public string AlertId { get; set; } = "";
}