# SecurityFramework Configuration Guide

## Overview

The SecurityFramework provides extensive configuration options to customize security behavior, performance characteristics, and feature enablement. Configuration follows the standard .NET configuration patterns with comprehensive validation and hot-reload support.

## Quick Start Configuration

### Basic Setup

```csharp
// Program.cs / Startup.cs
using SecurityFramework.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add SecurityFramework with basic configuration
builder.Services.AddSecurityFramework(options =>
{
    // Core settings
    options.EnableInMemoryStorage = true;
    options.DefaultThreatThreshold = 50;
    
    // IP Security
    options.IPSecurity.EnableBlocklist = true;
    options.IPSecurity.AutoBlockEnabled = true;
    
    // Parameter Security
    options.ParameterSecurity.EnableParameterJackingDetection = true;
    options.ParameterSecurity.DetectIDManipulation = true;
});

var app = builder.Build();

// Add middleware (must be early in pipeline)
app.UseSecurityFramework();

// Other middleware
app.UseAuthentication();
app.UseAuthorization();

app.Run();
```

### appsettings.json Configuration

```json
{
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": true,
    "SQLiteConnectionString": "Data Source=security.db;",
    "DefaultThreatThreshold": 50,
    "MaxIPRecords": 1000000,
    "DataRetentionDays": 90,
    
    "IPSecurity": {
      "EnableBlocklist": true,
      "AutoBlockEnabled": true,
      "AutoBlockThreshold": 75,
      "AutoBlockDuration": "24:00:00",
      "EnableGeoBlocking": false,
      "BlockedCountries": []
    },
    
    "ParameterSecurity": {
      "EnableParameterJackingDetection": true,
      "TrackParameterPatterns": true,
      "DetectIDManipulation": true,
      "DetectPathTraversal": true,
      "DetectSequentialAccess": true,
      "SequentialAccessThreshold": 5,
      "SequentialAccessWindow": "00:05:00",
      "MaxParameterAnomalyScore": 50,
      "AutoBlockOnHighRisk": true,
      "AutoBlockDuration": "24:00:00"
    },
    
    "Patterns": {
      "EnablePatternMatching": true,
      "PatternDirectory": "patterns/",
      "AutoReload": true,
      "ReloadInterval": "00:05:00"
    },
    
    "Performance": {
      "EnableCaching": true,
      "CacheExpirationMinutes": 60,
      "MaxConcurrentRequests": 10000,
      "EnableMetrics": true
    },
    
    "Notifications": {
      "EnableWebhooks": false,
      "EnableEmail": false,
      "CriticalThreshold": 75
    }
  }
}
```

## Core Configuration Options

### SecurityFrameworkOptions

Main configuration class with comprehensive options.

```csharp
public class SecurityFrameworkOptions : IValidatableObject
{
    /// <summary>
    /// Enable in-memory storage for high performance
    /// Default: true
    /// </summary>
    public bool EnableInMemoryStorage { get; set; } = true;

    /// <summary>
    /// Enable SQLite persistence for data durability
    /// Default: false
    /// </summary>
    public bool EnableSQLitePersistence { get; set; } = false;

    /// <summary>
    /// SQLite connection string (required if persistence enabled)
    /// Example: "Data Source=security.db;Cache=Shared;Mode=ReadWriteCreate;"
    /// </summary>
    [ConnectionString]
    public string? SQLiteConnectionString { get; set; }

    /// <summary>
    /// Default threat threshold for blocking decisions (0-100)
    /// Default: 50
    /// </summary>
    [Range(0, 100)]
    public double DefaultThreatThreshold { get; set; } = 50;

    /// <summary>
    /// Maximum number of IP records to keep in memory
    /// Default: 1,000,000
    /// </summary>
    [Range(1000, 10000000)]
    public int MaxIPRecords { get; set; } = 1000000;

    /// <summary>
    /// Data retention period in days
    /// Default: 90
    /// </summary>
    [Range(1, 365)]
    public int DataRetentionDays { get; set; } = 90;

    /// <summary>
    /// IP-based security configuration
    /// </summary>
    [Required]
    public IPSecurityOptions IPSecurity { get; set; } = new();

    /// <summary>
    /// Parameter jacking detection configuration
    /// </summary>
    [Required]
    public ParameterSecurityOptions ParameterSecurity { get; set; } = new();

    /// <summary>
    /// Pattern matching configuration
    /// </summary>
    public PatternOptions Patterns { get; set; } = new();

    /// <summary>
    /// Real-time monitoring configuration (optional)
    /// </summary>
    public RealTimeOptions? RealTimeMonitoring { get; set; }

    /// <summary>
    /// Machine learning configuration (optional)
    /// </summary>
    public MLOptions? MachineLearning { get; set; }

    /// <summary>
    /// Notification configuration
    /// </summary>
    public NotificationOptions Notifications { get; set; } = new();

    /// <summary>
    /// Performance and optimization settings
    /// </summary>
    public PerformanceOptions Performance { get; set; } = new();
}
```

## IP Security Configuration

### IPSecurityOptions

```csharp
public class IPSecurityOptions
{
    /// <summary>
    /// Enable IP blocklist functionality
    /// Default: true
    /// </summary>
    public bool EnableBlocklist { get; set; } = true;

    /// <summary>
    /// Enable automatic IP blocking based on threat scores
    /// Default: false
    /// </summary>
    public bool AutoBlockEnabled { get; set; } = false;

    /// <summary>
    /// Threat score threshold for automatic blocking (0-100)
    /// Default: 75
    /// </summary>
    [Range(0, 100)]
    public double AutoBlockThreshold { get; set; } = 75;

    /// <summary>
    /// Duration for automatic blocks
    /// Default: 24 hours
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "365.00:00:00")]
    public TimeSpan AutoBlockDuration { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Enable geographic IP blocking
    /// Default: false
    /// </summary>
    public bool EnableGeoBlocking { get; set; } = false;

    /// <summary>
    /// List of blocked country codes (ISO 3166-1 alpha-2)
    /// Example: ["CN", "RU", "KP"]
    /// </summary>
    public string[] BlockedCountries { get; set; } = Array.Empty<string>();

    /// <summary>
    /// List of allowed country codes (if specified, only these are allowed)
    /// Example: ["US", "CA", "GB"]
    /// </summary>
    public string[]? AllowedCountries { get; set; }

    /// <summary>
    /// Block known Tor exit nodes
    /// Default: false
    /// </summary>
    public bool BlockTorExitNodes { get; set; } = false;

    /// <summary>
    /// Block known hosting/cloud provider IPs
    /// Default: false
    /// </summary>
    public bool BlockHostingProviders { get; set; } = false;

    /// <summary>
    /// Allow private network IPs (192.168.x.x, 10.x.x.x, etc.)
    /// Default: true
    /// </summary>
    public bool AllowPrivateNetworks { get; set; } = true;

    /// <summary>
    /// Trusted IP ranges that bypass all security checks
    /// Format: ["192.168.1.0/24", "10.0.0.0/8"]
    /// </summary>
    public string[] TrustedIPRanges { get; set; } = Array.Empty<string>();

    /// <summary>
    /// External blocklist sources
    /// </summary>
    public ExternalBlocklistOptions ExternalBlocklists { get; set; } = new();

    /// <summary>
    /// Rate limiting configuration
    /// </summary>
    public RateLimitOptions RateLimit { get; set; } = new();
}
```

### Example IP Security Configuration

```json
{
  "SecurityFramework": {
    "IPSecurity": {
      "EnableBlocklist": true,
      "AutoBlockEnabled": true,
      "AutoBlockThreshold": 75,
      "AutoBlockDuration": "24:00:00",
      "EnableGeoBlocking": true,
      "BlockedCountries": ["CN", "RU", "KP", "IR"],
      "BlockTorExitNodes": true,
      "BlockHostingProviders": false,
      "AllowPrivateNetworks": true,
      "TrustedIPRanges": [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12"
      ],
      "ExternalBlocklists": {
        "EnableSpamhaus": true,
        "EnableEmergingThreats": true,
        "CustomSources": [
          {
            "Name": "CompanyBlocklist",
            "Url": "https://security.company.com/blocklist.txt",
            "Format": "PlainText",
            "UpdateInterval": "01:00:00"
          }
        ]
      },
      "RateLimit": {
        "EnableRateLimit": true,
        "RequestsPerMinute": 300,
        "BurstSize": 50,
        "WindowSize": "00:01:00"
      }
    }
  }
}
```

## Parameter Security Configuration

### ParameterSecurityOptions

```csharp
public class ParameterSecurityOptions
{
    /// <summary>
    /// Enable parameter jacking detection
    /// Default: true
    /// </summary>
    public bool EnableParameterJackingDetection { get; set; } = true;

    /// <summary>
    /// Track parameter access patterns for analysis
    /// Default: true
    /// </summary>
    public bool TrackParameterPatterns { get; set; } = true;

    /// <summary>
    /// Detect ID manipulation attempts
    /// Default: true
    /// </summary>
    public bool DetectIDManipulation { get; set; } = true;

    /// <summary>
    /// Detect path traversal in parameters
    /// Default: true
    /// </summary>
    public bool DetectPathTraversal { get; set; } = true;

    /// <summary>
    /// Detect sequential access patterns
    /// Default: true
    /// </summary>
    public bool DetectSequentialAccess { get; set; } = true;

    /// <summary>
    /// Number of sequential accesses to trigger detection
    /// Default: 5
    /// </summary>
    [Range(3, 100)]
    public int SequentialAccessThreshold { get; set; } = 5;

    /// <summary>
    /// Time window for sequential access detection
    /// Default: 5 minutes
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "24:00:00")]
    public TimeSpan SequentialAccessWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum parameter anomaly score before blocking
    /// Default: 50
    /// </summary>
    [Range(0, 100)]
    public double MaxParameterAnomalyScore { get; set; } = 50;

    /// <summary>
    /// Automatically block IPs with high parameter jacking risk
    /// Default: true
    /// </summary>
    public bool AutoBlockOnHighRisk { get; set; } = true;

    /// <summary>
    /// Duration for automatic parameter jacking blocks
    /// Default: 24 hours
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "30.00:00:00")]
    public TimeSpan AutoBlockDuration { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Email address for security alerts
    /// </summary>
    [EmailAddress]
    public string? SecurityAlertEmail { get; set; }

    /// <summary>
    /// Protected parameter configurations
    /// </summary>
    public ICollection<ProtectedParameter> ProtectedParameters { get; set; } = new List<ProtectedParameter>();

    /// <summary>
    /// User context validation settings
    /// </summary>
    public UserContextOptions UserContext { get; set; } = new();
}
```

### Protected Parameter Configuration

```csharp
public class ProtectedParameter
{
    /// <summary>
    /// Parameter name to protect
    /// </summary>
    [Required]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Parameter type for validation
    /// </summary>
    public ParameterType Type { get; set; } = ParameterType.UserContext;

    /// <summary>
    /// Regular expression pattern for validation
    /// </summary>
    public string? Pattern { get; set; }

    /// <summary>
    /// Require user ownership validation
    /// </summary>
    public bool RequireOwnership { get; set; } = true;

    /// <summary>
    /// Allow administrative override
    /// </summary>
    public bool AllowAdminOverride { get; set; } = true;

    /// <summary>
    /// Custom validation logic type
    /// </summary>
    public string? CustomValidatorType { get; set; }
}
```

### Example Parameter Security Configuration

```json
{
  "SecurityFramework": {
    "ParameterSecurity": {
      "EnableParameterJackingDetection": true,
      "TrackParameterPatterns": true,
      "DetectIDManipulation": true,
      "DetectPathTraversal": true,
      "DetectSequentialAccess": true,
      "SequentialAccessThreshold": 5,
      "SequentialAccessWindow": "00:05:00",
      "MaxParameterAnomalyScore": 50,
      "AutoBlockOnHighRisk": true,
      "AutoBlockDuration": "24:00:00",
      "SecurityAlertEmail": "security@company.com",
      "ProtectedParameters": [
        {
          "Name": "user_id",
          "Type": "UserContext",
          "RequireOwnership": true,
          "AllowAdminOverride": true
        },
        {
          "Name": "order_id",
          "Type": "UserContext",
          "RequireOwnership": true,
          "AllowAdminOverride": false
        },
        {
          "Name": "account_id",
          "Type": "UserContext",
          "Pattern": "^[0-9]+$",
          "RequireOwnership": true,
          "AllowAdminOverride": true
        },
        {
          "Name": "file_path",
          "Type": "PathValidation",
          "Pattern": "^[a-zA-Z0-9/_.-]+$",
          "RequireOwnership": false,
          "AllowAdminOverride": true
        }
      ],
      "UserContext": {
        "EnableUserContextValidation": true,
        "UserIdClaim": "sub",
        "RoleClaim": "role",
        "AdminRoles": ["admin", "security"]
      }
    }
  }
}
```

## Pattern Configuration

### PatternOptions

```csharp
public class PatternOptions
{
    /// <summary>
    /// Enable pattern matching functionality
    /// Default: true
    /// </summary>
    public bool EnablePatternMatching { get; set; } = true;

    /// <summary>
    /// Directory containing pattern JSON files
    /// Default: "patterns/"
    /// </summary>
    public string PatternDirectory { get; set; } = "patterns/";

    /// <summary>
    /// Enable automatic pattern reloading
    /// Default: true
    /// </summary>
    public bool AutoReload { get; set; } = true;

    /// <summary>
    /// Pattern reload check interval
    /// Default: 5 minutes
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "24:00:00")]
    public TimeSpan ReloadInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum number of patterns to load
    /// Default: 10,000
    /// </summary>
    [Range(1, 100000)]
    public int MaxPatterns { get; set; } = 10000;

    /// <summary>
    /// Enable pattern compilation for performance
    /// Default: true
    /// </summary>
    public bool CompilePatterns { get; set; } = true;

    /// <summary>
    /// Pattern matching timeout per pattern
    /// Default: 100ms
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00.001", "00:00:10")]
    public TimeSpan MatchTimeout { get; set; } = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Default patterns to load on startup
    /// </summary>
    public DefaultPatternOptions DefaultPatterns { get; set; } = new();

    /// <summary>
    /// External pattern sources
    /// </summary>
    public ExternalPatternOptions ExternalSources { get; set; } = new();
}
```

### Example Pattern Configuration

```json
{
  "SecurityFramework": {
    "Patterns": {
      "EnablePatternMatching": true,
      "PatternDirectory": "patterns/",
      "AutoReload": true,
      "ReloadInterval": "00:05:00",
      "MaxPatterns": 10000,
      "CompilePatterns": true,
      "MatchTimeout": "00:00:00.100",
      "DefaultPatterns": {
        "LoadOWASPTop10": true,
        "LoadBotPatterns": true,
        "LoadSQLInjection": true,
        "LoadXSSPatterns": true,
        "LoadPathTraversal": true,
        "LoadParameterJacking": true
      },
      "ExternalSources": [
        {
          "Name": "OWASP-CRS",
          "Url": "https://github.com/coreruleset/coreruleset/archive/v3.3.2.zip",
          "Format": "ModSecurity",
          "UpdateInterval": "24:00:00",
          "Enabled": false
        },
        {
          "Name": "CompanyPatterns",
          "Url": "https://security.company.com/patterns.json",
          "Format": "SecurityFramework",
          "UpdateInterval": "01:00:00",
          "Enabled": true
        }
      ]
    }
  }
}
```

## Real-Time Configuration (Optional)

### RealTimeOptions

```csharp
public class RealTimeOptions
{
    /// <summary>
    /// Enable real-time monitoring features
    /// Default: false
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Enable SignalR for real-time communication
    /// Default: true (if real-time enabled)
    /// </summary>
    public bool EnableSignalR { get; set; } = true;

    /// <summary>
    /// Enable WebSocket support
    /// Default: true (if real-time enabled)
    /// </summary>
    public bool EnableWebSockets { get; set; } = true;

    /// <summary>
    /// Require authentication for real-time connections
    /// Default: true
    /// </summary>
    public bool AuthenticateConnections { get; set; } = true;

    /// <summary>
    /// Maximum connections per IP address
    /// Default: 10
    /// </summary>
    [Range(1, 1000)]
    public int MaxConnectionsPerIP { get; set; } = 10;

    /// <summary>
    /// Connection timeout duration
    /// Default: 5 minutes
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:30", "01:00:00")]
    public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// SignalR configuration
    /// </summary>
    public SignalROptions SignalR { get; set; } = new();

    /// <summary>
    /// WebSocket configuration
    /// </summary>
    public WebSocketOptions WebSocket { get; set; } = new();

    /// <summary>
    /// Event broadcasting configuration
    /// </summary>
    public EventBroadcastOptions Events { get; set; } = new();
}
```

### Example Real-Time Configuration

```json
{
  "SecurityFramework": {
    "RealTimeMonitoring": {
      "Enabled": true,
      "EnableSignalR": true,
      "EnableWebSockets": true,
      "AuthenticateConnections": true,
      "MaxConnectionsPerIP": 10,
      "ConnectionTimeout": "00:05:00",
      "SignalR": {
        "EnableDetailedErrors": false,
        "MaxReceiveMessageSize": 32768,
        "StreamBufferCapacity": 10,
        "EnableRedisBackplane": true,
        "RedisConnectionString": "localhost:6379"
      },
      "WebSocket": {
        "KeepAliveInterval": "00:00:30",
        "ReceiveBufferSize": 4096,
        "SendBufferSize": 4096,
        "AllowedOrigins": ["https://dashboard.company.com"]
      },
      "Events": {
        "BroadcastThreatDetection": true,
        "BroadcastIPBlocks": true,
        "BroadcastPatternMatches": false,
        "BroadcastMetrics": true,
        "MetricsBroadcastInterval": "00:00:10"
      }
    }
  }
}
```

## Performance Configuration

### PerformanceOptions

```csharp
public class PerformanceOptions
{
    /// <summary>
    /// Enable caching for improved performance
    /// Default: true
    /// </summary>
    public bool EnableCaching { get; set; } = true;

    /// <summary>
    /// Cache expiration time in minutes
    /// Default: 60 minutes
    /// </summary>
    [Range(1, 1440)]
    public int CacheExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Maximum concurrent requests to process
    /// Default: 10,000
    /// </summary>
    [Range(100, 100000)]
    public int MaxConcurrentRequests { get; set; } = 10000;

    /// <summary>
    /// Enable performance metrics collection
    /// Default: true
    /// </summary>
    public bool EnableMetrics { get; set; } = true;

    /// <summary>
    /// Background processing configuration
    /// </summary>
    public BackgroundProcessingOptions BackgroundProcessing { get; set; } = new();

    /// <summary>
    /// Database optimization settings
    /// </summary>
    public DatabaseOptions Database { get; set; } = new();

    /// <summary>
    /// Memory optimization settings
    /// </summary>
    public MemoryOptions Memory { get; set; } = new();
}
```

### Example Performance Configuration

```json
{
  "SecurityFramework": {
    "Performance": {
      "EnableCaching": true,
      "CacheExpirationMinutes": 60,
      "MaxConcurrentRequests": 10000,
      "EnableMetrics": true,
      "BackgroundProcessing": {
        "EnableBackgroundTasks": true,
        "PersistenceInterval": "00:05:00",
        "CleanupInterval": "01:00:00",
        "AnalyticsInterval": "00:15:00",
        "MaxBackgroundTasks": 10
      },
      "Database": {
        "EnableConnectionPooling": true,
        "MaxPoolSize": 100,
        "CommandTimeout": "00:00:30",
        "EnableWAL": true,
        "CacheSize": 1000,
        "PageSize": 4096
      },
      "Memory": {
        "EnableObjectPooling": true,
        "MaxObjectsPerPool": 1000,
        "GCSettings": {
          "LatencyMode": "Interactive",
          "EnableConcurrentGC": true
        }
      }
    }
  }
}
```

## Notification Configuration

### NotificationOptions

```csharp
public class NotificationOptions
{
    /// <summary>
    /// Enable webhook notifications
    /// Default: false
    /// </summary>
    public bool EnableWebhooks { get; set; } = false;

    /// <summary>
    /// Enable email notifications
    /// Default: false
    /// </summary>
    public bool EnableEmail { get; set; } = false;

    /// <summary>
    /// Threat score threshold for critical notifications
    /// Default: 75
    /// </summary>
    [Range(0, 100)]
    public double CriticalThreshold { get; set; } = 75;

    /// <summary>
    /// Webhook configurations
    /// </summary>
    public ICollection<WebhookConfiguration> Webhooks { get; set; } = new List<WebhookConfiguration>();

    /// <summary>
    /// Email configuration
    /// </summary>
    public EmailOptions Email { get; set; } = new();

    /// <summary>
    /// Notification throttling settings
    /// </summary>
    public ThrottlingOptions Throttling { get; set; } = new();
}
```

### Example Notification Configuration

```json
{
  "SecurityFramework": {
    "Notifications": {
      "EnableWebhooks": true,
      "EnableEmail": true,
      "CriticalThreshold": 75,
      "Webhooks": [
        {
          "Name": "SecurityTeam",
          "Url": "https://hooks.slack.com/services/...",
          "Events": ["ThreatDetected", "IPBlocked", "CriticalIncident"],
          "Secret": "webhook-secret-key",
          "Headers": {
            "Authorization": "Bearer token-here"
          },
          "Timeout": "00:00:30",
          "RetryCount": 3
        },
        {
          "Name": "SOC",
          "Url": "https://soc.company.com/webhook",
          "Events": ["HighThreat", "ParameterJacking"],
          "Format": "JSON",
          "Enabled": true
        }
      ],
      "Email": {
        "SmtpServer": "smtp.company.com",
        "SmtpPort": 587,
        "Username": "security@company.com",
        "EnableSSL": true,
        "FromAddress": "security@company.com",
        "ToAddresses": ["soc@company.com", "admin@company.com"],
        "SubjectPrefix": "[SecurityFramework]"
      },
      "Throttling": {
        "EnableThrottling": true,
        "MaxNotificationsPerHour": 100,
        "DuplicateSuppressionMinutes": 15
      }
    }
  }
}
```

## Environment-Specific Configuration

### Development Environment

```json
{
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": false,
    "DefaultThreatThreshold": 25,
    "IPSecurity": {
      "AutoBlockEnabled": false,
      "EnableGeoBlocking": false,
      "AllowPrivateNetworks": true
    },
    "ParameterSecurity": {
      "AutoBlockOnHighRisk": false,
      "SequentialAccessThreshold": 10
    },
    "Patterns": {
      "AutoReload": true,
      "ReloadInterval": "00:01:00"
    },
    "Performance": {
      "EnableMetrics": true,
      "MaxConcurrentRequests": 1000
    },
    "RealTimeMonitoring": {
      "Enabled": true,
      "AuthenticateConnections": false
    }
  }
}
```

### Production Environment

```json
{
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": true,
    "SQLiteConnectionString": "Data Source=/data/security.db;Cache=Shared;Mode=ReadWriteCreate;",
    "DefaultThreatThreshold": 50,
    "DataRetentionDays": 90,
    "IPSecurity": {
      "AutoBlockEnabled": true,
      "AutoBlockThreshold": 75,
      "EnableGeoBlocking": true,
      "BlockedCountries": ["CN", "RU", "KP"],
      "BlockTorExitNodes": true
    },
    "ParameterSecurity": {
      "AutoBlockOnHighRisk": true,
      "SecurityAlertEmail": "security@company.com"
    },
    "Patterns": {
      "AutoReload": false,
      "CompilePatterns": true
    },
    "Performance": {
      "MaxConcurrentRequests": 50000,
      "BackgroundProcessing": {
        "PersistenceInterval": "00:05:00"
      }
    },
    "RealTimeMonitoring": {
      "Enabled": true,
      "AuthenticateConnections": true,
      "SignalR": {
        "EnableRedisBackplane": true,
        "RedisConnectionString": "redis-cluster:6379"
      }
    },
    "Notifications": {
      "EnableWebhooks": true,
      "EnableEmail": true
    }
  }
}
```

## Advanced Configuration Patterns

### Configuration Validation

```csharp
// Custom configuration validation
public class CustomSecurityFrameworkOptionsValidator : IValidateOptions<SecurityFrameworkOptions>
{
    public ValidateOptionsResult Validate(string name, SecurityFrameworkOptions options)
    {
        var failures = new List<string>();

        // Custom validation logic
        if (options.EnableSQLitePersistence && string.IsNullOrEmpty(options.SQLiteConnectionString))
        {
            failures.Add("SQLite connection string is required when persistence is enabled");
        }

        if (options.RealTimeMonitoring?.Enabled == true)
        {
            if (!options.RealTimeMonitoring.EnableSignalR && !options.RealTimeMonitoring.EnableWebSockets)
            {
                failures.Add("At least one real-time transport must be enabled");
            }
        }

        if (options.DefaultThreatThreshold > 95)
        {
            failures.Add("Threat threshold above 95 may cause excessive blocking");
        }

        return failures.Count > 0 
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}

// Register custom validator
services.AddSingleton<IValidateOptions<SecurityFrameworkOptions>, CustomSecurityFrameworkOptionsValidator>();
```

### Hot Configuration Reload

```csharp
// Enable configuration hot-reload
services.Configure<SecurityFrameworkOptions>(
    builder.Configuration.GetSection("SecurityFramework"));

// Monitor configuration changes
services.AddSingleton<IOptionsMonitor<SecurityFrameworkOptions>>();

// In your service
public class SecurityService : ISecurityService
{
    private readonly IOptionsMonitor<SecurityFrameworkOptions> _optionsMonitor;

    public SecurityService(IOptionsMonitor<SecurityFrameworkOptions> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
        _optionsMonitor.OnChange(OnConfigurationChanged);
    }

    private void OnConfigurationChanged(SecurityFrameworkOptions options)
    {
        // Handle configuration changes
        ReloadPatterns();
        UpdateThresholds(options);
        // ... other updates
    }
}
```

### Configuration Secrets Management

```csharp
// Use Azure Key Vault for secrets
builder.Configuration.AddAzureKeyVault(
    new Uri("https://your-keyvault.vault.azure.net/"),
    new DefaultAzureCredential());

// Use environment variables for sensitive data
{
  "SecurityFramework": {
    "SQLiteConnectionString": "${SECURITY_DB_CONNECTION}",
    "Notifications": {
      "Email": {
        "Password": "${SMTP_PASSWORD}"
      },
      "Webhooks": [
        {
          "Secret": "${WEBHOOK_SECRET}"
        }
      ]
    }
  }
}
```

### Feature Flags Integration

```csharp
// Enable feature flags
services.AddFeatureManagement();

// Conditional configuration based on feature flags
services.AddSecurityFramework(options =>
{
    var featureManager = serviceProvider.GetRequiredService<IFeatureManager>();
    
    if (featureManager.IsEnabledAsync("AdvancedThreatDetection").Result)
    {
        options.DefaultThreatThreshold = 40;
        options.ParameterSecurity.SequentialAccessThreshold = 3;
    }
    
    if (featureManager.IsEnabledAsync("RealTimeMonitoring").Result)
    {
        options.RealTimeMonitoring = new RealTimeOptions { Enabled = true };
    }
});
```

## Configuration Best Practices

### Security Best Practices

1. **Store Secrets Securely**: Never put passwords, API keys, or secrets in configuration files
2. **Use HTTPS**: Always use HTTPS for webhook URLs and external connections
3. **Validate Input**: Enable comprehensive validation for all configuration options
4. **Principle of Least Privilege**: Only enable features you actually need
5. **Monitor Configuration Changes**: Log all configuration changes for audit trails

### Performance Best Practices

1. **Enable Caching**: Use caching for better performance in production
2. **Tune Thresholds**: Adjust thresholds based on your specific traffic patterns
3. **Monitor Memory Usage**: Set appropriate limits for IP records and patterns
4. **Use SQLite Persistence**: Enable persistence for production environments
5. **Optimize Background Tasks**: Configure appropriate intervals for background processing

### Operational Best Practices

1. **Start Conservative**: Begin with lower thresholds and gradually increase
2. **Monitor False Positives**: Track and adjust configuration to minimize false positives
3. **Test Configuration**: Validate configuration changes in staging environments
4. **Document Changes**: Maintain documentation for all configuration modifications
5. **Regular Review**: Periodically review and update configuration as needed

---

> **Next Steps**: After configuration, see the [Integration Guide](Integration-Guide.md) for implementing the framework in your application, and [Pattern Development](Pattern-Development.md) for creating custom threat patterns.