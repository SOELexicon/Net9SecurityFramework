# SecurityFramework Basic Usage Examples

## Overview

This guide provides practical examples for integrating and using the SecurityFramework in your ASP.NET Core applications. These examples focus on common scenarios and quick implementation patterns.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Configuration](#basic-configuration)
3. [Simple Integration](#simple-integration)
4. [IP Security Examples](#ip-security-examples)
5. [Pattern Matching Examples](#pattern-matching-examples)
6. [Parameter Security Examples](#parameter-security-examples)
7. [Rate Limiting Examples](#rate-limiting-examples)
8. [Behavioral Analysis Examples](#behavioral-analysis-examples)
9. [Common Use Cases](#common-use-cases)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Installation

```bash
# Install the SecurityFramework NuGet package
dotnet add package SecurityFramework

# Install Entity Framework Core for SQLite (optional for persistence)
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
```

### 2. Minimal Setup

```csharp
// Program.cs (ASP.NET Core 6+)
using SecurityFramework;

var builder = WebApplication.CreateBuilder(args);

// Add SecurityFramework services
builder.Services.AddSecurityFramework(builder.Configuration);

// Add other services
builder.Services.AddControllers();

var app = builder.Build();

// Add SecurityFramework middleware (order matters!)
app.UseSecurityFramework();

// Add other middleware
app.UseRouting();
app.MapControllers();

app.Run();
```

### 3. Basic Configuration

```json
{
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "DefaultThreatThreshold": 50,
    "IPSecurity": {
      "EnableBlocklist": true,
      "AutoBlockEnabled": false
    },
    "Patterns": {
      "EnablePatternMatching": true,
      "PatternDirectory": "patterns/"
    }
  }
}
```

## Basic Configuration

### Development Environment

```json
{
  "ConnectionStrings": {
    "SecurityFramework": "Data Source=security-dev.db"
  },
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": false,
    "DefaultThreatThreshold": 30,
    "IPSecurity": {
      "EnableBlocklist": true,
      "AutoBlockEnabled": false,
      "AllowPrivateNetworks": true,
      "TrustedIPRanges": [
        "127.0.0.1/32",
        "192.168.1.0/24",
        "10.0.0.0/8"
      ]
    },
    "Patterns": {
      "EnablePatternMatching": true,
      "DefaultPatterns": {
        "LoadOWASPTop10": true,
        "LoadSQLInjection": true,
        "LoadXSSPatterns": true
      }
    },
    "ParameterSecurity": {
      "EnableParameterJackingDetection": true,
      "DetectIDManipulation": true,
      "AutoBlockOnHighRisk": false
    }
  }
}
```

### Production Environment

```json
{
  "ConnectionStrings": {
    "SecurityFramework": "Data Source=/app/data/security.db"
  },
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": true,
    "DefaultThreatThreshold": 60,
    "IPSecurity": {
      "EnableBlocklist": true,
      "AutoBlockEnabled": true,
      "AutoBlockThreshold": 80,
      "AutoBlockDuration": "24:00:00",
      "AllowPrivateNetworks": false,
      "TrustedIPRanges": [
        "10.0.0.0/16"
      ]
    },
    "Patterns": {
      "EnablePatternMatching": true,
      "CompilePatterns": true,
      "DefaultPatterns": {
        "LoadOWASPTop10": true,
        "LoadBotPatterns": true,
        "LoadSQLInjection": true,
        "LoadXSSPatterns": true,
        "LoadPathTraversal": true
      }
    },
    "ParameterSecurity": {
      "EnableParameterJackingDetection": true,
      "AutoBlockOnHighRisk": true,
      "MaxParameterAnomalyScore": 70
    },
    "Notifications": {
      "EnableEmail": true,
      "EnableWebhooks": true,
      "CriticalThreshold": 85
    }
  }
}
```

## Simple Integration

### Basic Web API Setup

```csharp
// Program.cs
using SecurityFramework;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add SecurityFramework
builder.Services.AddSecurityFramework(builder.Configuration);

var app = builder.Build();

// Configure pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Security middleware (early in pipeline)
app.UseSecurityFramework();

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

### Simple Controller with Security

```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly ISecurityService _securityService;
    private readonly ILogger<UsersController> _logger;
    
    public UsersController(ISecurityService securityService, ILogger<UsersController> logger)
    {
        _securityService = securityService;
        _logger = logger;
    }
    
    [HttpGet("{id}")]
    [ParameterSecurity("id", RequireOwnership = true)]
    public async Task<ActionResult<User>> GetUser(int id)
    {
        // SecurityFramework automatically validates the 'id' parameter
        // and ensures the current user owns this resource
        
        var user = await GetUserByIdAsync(id);
        return Ok(user);
    }
    
    [HttpGet("search")]
    public async Task<ActionResult<List<User>>> SearchUsers([FromQuery] string query)
    {
        // SecurityFramework automatically scans the query parameter
        // for SQL injection and XSS patterns
        
        var users = await SearchUsersAsync(query);
        return Ok(users);
    }
    
    [HttpPost]
    public async Task<ActionResult<User>> CreateUser([FromBody] CreateUserRequest request)
    {
        // SecurityFramework scans the request body for malicious patterns
        
        var user = await CreateUserAsync(request);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }
}
```

### Manual Security Checks

```csharp
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    private readonly ISecurityService _securityService;
    
    public OrdersController(ISecurityService securityService)
    {
        _securityService = securityService;
    }
    
    [HttpGet("{id}")]
    public async Task<ActionResult<Order>> GetOrder(int id)
    {
        // Manual IP assessment
        var clientIP = HttpContext.Connection.RemoteIpAddress?.ToString();
        var ipAssessment = await _securityService.AssessIPAsync(clientIP);
        
        if (ipAssessment.ThreatScore > 80)
        {
            return Forbid("High-risk IP address");
        }
        
        // Manual parameter validation
        var userContext = new UserContext
        {
            UserId = User.Identity?.Name,
            Roles = User.Claims.Where(c => c.Type == "role").Select(c => c.Value).ToList()
        };
        
        var parameterValidation = await _securityService.ValidateParameterAsync(
            "id", id.ToString(), userContext, "Order");
            
        if (parameterValidation.IsViolation)
        {
            return Forbid("Unauthorized access to resource");
        }
        
        var order = await GetOrderByIdAsync(id);
        return Ok(order);
    }
}
```

## IP Security Examples

### Basic IP Blocking

```csharp
public class AdminController : ControllerBase
{
    private readonly IIPSecurityService _ipSecurityService;
    
    [HttpPost("block-ip")]
    public async Task<IActionResult> BlockIP([FromBody] BlockIPRequest request)
    {
        await _ipSecurityService.BlockIPAsync(
            request.IPAddress, 
            request.Reason, 
            TimeSpan.FromHours(request.DurationHours));
            
        return Ok(new { message = "IP blocked successfully" });
    }
    
    [HttpPost("unblock-ip")]
    public async Task<IActionResult> UnblockIP([FromBody] UnblockIPRequest request)
    {
        await _ipSecurityService.UnblockIPAsync(request.IPAddress);
        return Ok(new { message = "IP unblocked successfully" });
    }
    
    [HttpGet("ip-status/{ip}")]
    public async Task<ActionResult<IPStatusResponse>> GetIPStatus(string ip)
    {
        var assessment = await _ipSecurityService.AssessIPAsync(ip);
        
        return Ok(new IPStatusResponse
        {
            IPAddress = ip,
            ThreatScore = assessment.ThreatScore,
            TrustScore = assessment.TrustScore,
            IsBlocked = assessment.IsBlocked,
            BlockReason = assessment.BlockReason,
            RequestCount = assessment.RequestCount,
            LastActivity = assessment.LastActivity
        });
    }
}

public class BlockIPRequest
{
    public string IPAddress { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public int DurationHours { get; set; } = 24;
}

public class IPStatusResponse
{
    public string IPAddress { get; set; } = string.Empty;
    public double ThreatScore { get; set; }
    public double TrustScore { get; set; }
    public bool IsBlocked { get; set; }
    public string? BlockReason { get; set; }
    public int RequestCount { get; set; }
    public DateTime? LastActivity { get; set; }
}
```

### Trusted IP Configuration

```csharp
// Startup or Program.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddSecurityFramework(Configuration);
    
    // Configure trusted IPs programmatically
    services.Configure<SecurityFrameworkOptions>(options =>
    {
        options.IPSecurity.TrustedIPRanges.AddRange(new[]
        {
            "192.168.1.0/24",    // Local network
            "10.0.0.0/8",        // Private network
            "172.16.0.0/12",     // Docker networks
            "203.0.113.0/24"     // Office IP range
        });
    });
}
```

### Geographic Blocking

```json
{
  "SecurityFramework": {
    "IPSecurity": {
      "EnableGeoBlocking": true,
      "BlockedCountries": ["CN", "RU", "KP"],
      "BlockTorExitNodes": true,
      "BlockHostingProviders": true
    }
  }
}
```

## Pattern Matching Examples

### Custom Pattern Definition

```json
{
  "name": "Credit Card Detection",
  "pattern": "\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b",
  "type": "Regex",
  "category": "DataExposure",
  "threatMultiplier": 60,
  "isActive": true,
  "description": "Detects credit card numbers in requests",
  "metadata": {
    "severity": "high",
    "confidence": 0.85,
    "references": ["PCI-DSS"],
    "testCases": [
      {
        "input": "4532-1234-5678-9012",
        "shouldMatch": true,
        "description": "Standard credit card format"
      },
      {
        "input": "4532 1234 5678 9012",
        "shouldMatch": true,
        "description": "Space-separated format"
      },
      {
        "input": "normal text",
        "shouldMatch": false,
        "description": "No credit card number"
      }
    ]
  }
}
```

### SQL Injection Detection

```csharp
[HttpGet("products")]
public async Task<ActionResult<List<Product>>> SearchProducts([FromQuery] string search)
{
    // SecurityFramework automatically scans for SQL injection patterns
    // Built-in patterns include:
    // - UNION SELECT attacks
    // - Boolean-based injection
    // - Time-based injection
    // - Stacked queries
    
    // If a threat is detected, the request is blocked before reaching this code
    
    var products = await _productService.SearchAsync(search);
    return Ok(products);
}
```

### XSS Prevention

```csharp
[HttpPost("comments")]
public async Task<ActionResult<Comment>> PostComment([FromBody] CommentRequest request)
{
    // SecurityFramework scans request.Content for XSS patterns:
    // - Script tags
    // - Event handlers (onclick, onload, etc.)
    // - JavaScript: protocols
    // - Data: URLs with JavaScript
    
    var comment = new Comment
    {
        Content = request.Content, // Already validated by SecurityFramework
        UserId = GetCurrentUserId(),
        PostId = request.PostId,
        CreatedAt = DateTime.UtcNow
    };
    
    await _commentService.CreateAsync(comment);
    return CreatedAtAction(nameof(GetComment), new { id = comment.Id }, comment);
}
```

### Custom Pattern Loading

```csharp
public class PatternManagementController : ControllerBase
{
    private readonly IPatternMatchingService _patternService;
    
    [HttpPost("patterns")]
    public async Task<IActionResult> LoadCustomPattern([FromBody] ThreatPattern pattern)
    {
        // Validate pattern before loading
        var validation = await _patternService.ValidatePatternAsync(pattern);
        if (!validation.IsValid)
        {
            return BadRequest(validation.Errors);
        }
        
        await _patternService.LoadPatternAsync(pattern);
        return Ok(new { message = "Pattern loaded successfully" });
    }
    
    [HttpGet("patterns")]
    public async Task<ActionResult<List<PatternSummary>>> GetActivePatterns()
    {
        var patterns = await _patternService.GetActivePatternsAsync();
        return Ok(patterns.Select(p => new PatternSummary
        {
            Name = p.Name,
            Category = p.Category,
            ThreatMultiplier = p.ThreatMultiplier,
            MatchCount = p.MatchCount,
            LastMatched = p.LastMatchedAt
        }));
    }
}
```

## Parameter Security Examples

### Basic IDOR Prevention

```csharp
[HttpGet("users/{id}/profile")]
[ParameterSecurity("id", RequireOwnership = true)]
public async Task<ActionResult<UserProfile>> GetUserProfile(int id)
{
    // SecurityFramework automatically:
    // 1. Validates that the current user owns user ID {id}
    // 2. Checks for sequential access patterns
    // 3. Detects ID manipulation attempts
    
    var profile = await _userService.GetProfileAsync(id);
    return Ok(profile);
}

[HttpGet("orders/{orderId}")]
[ParameterSecurity("orderId", RequireOwnership = true, ResourceType = "Order")]
public async Task<ActionResult<Order>> GetOrder(int orderId)
{
    // Uses custom ownership validation for Order resources
    var order = await _orderService.GetByIdAsync(orderId);
    return Ok(order);
}
```

### Advanced Parameter Protection

```csharp
[HttpGet("documents/{documentId}")]
[ParameterSecurity("documentId", 
    RequireOwnership = true, 
    AllowAdminOverride = true,
    DetectSequentialAccess = true)]
public async Task<ActionResult<Document>> GetDocument(int documentId)
{
    // SecurityFramework provides:
    // - Ownership validation
    // - Admin role bypass
    // - Sequential access detection (1, 2, 3, 4...)
    
    var document = await _documentService.GetByIdAsync(documentId);
    return Ok(document);
}
```

### Custom Parameter Validation

```csharp
public class CustomParameterValidator : IParameterValidator
{
    public async Task<ParameterValidationResult> ValidateAsync(
        string parameterName, 
        string parameterValue, 
        UserContext userContext)
    {
        if (parameterName == "customerId")
        {
            // Custom business logic validation
            var hasAccess = await ValidateCustomerAccessAsync(
                parameterValue, userContext.UserId);
                
            if (!hasAccess)
            {
                return ParameterValidationResult.Violation(
                    "Unauthorized customer access",
                    ParameterJackingType.PrivilegeEscalation,
                    85);
            }
        }
        
        return ParameterValidationResult.Valid();
    }
}

// Register in Startup.cs
services.AddSingleton<IParameterValidator, CustomParameterValidator>();
```

## Rate Limiting Examples

### Basic Rate Limiting

```json
{
  "SecurityFramework": {
    "IPSecurity": {
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

### Endpoint-Specific Rate Limiting

```csharp
[HttpPost("login")]
[RateLimit(RequestsPerMinute = 5, BurstSize = 2)]
public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request)
{
    // Strict rate limiting for login attempts
    var result = await _authService.LoginAsync(request.Email, request.Password);
    return Ok(result);
}

[HttpGet("search")]
[RateLimit(RequestsPerMinute = 100)]
public async Task<ActionResult<SearchResults>> Search([FromQuery] string query)
{
    // More permissive rate limiting for search
    var results = await _searchService.SearchAsync(query);
    return Ok(results);
}
```

### User-Based Rate Limiting

```csharp
[HttpPost("api/upload")]
[RateLimit(RequestsPerMinute = 10, RateLimitType = RateLimitType.PerUser)]
public async Task<IActionResult> UploadFile(IFormFile file)
{
    // Rate limit per authenticated user
    await _fileService.UploadAsync(file, GetCurrentUserId());
    return Ok();
}
```

## Behavioral Analysis Examples

### User Behavior Monitoring

```csharp
public class AccountController : ControllerBase
{
    private readonly IBehavioralAnalysisService _behaviorService;
    
    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request)
    {
        // Check for anomalous login behavior
        var behaviorAnalysis = await _behaviorService.AnalyzeLoginBehaviorAsync(
            request.Email, 
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers["User-Agent"]);
            
        if (behaviorAnalysis.IsAnomalous && behaviorAnalysis.AnomalyScore > 70)
        {
            // Require additional verification
            return Ok(new LoginResponse 
            { 
                RequiresMFA = true,
                AnomalyDetected = true 
            });
        }
        
        var result = await _authService.LoginAsync(request.Email, request.Password);
        return Ok(result);
    }
}
```

### Geographic Anomaly Detection

```csharp
[HttpGet("sensitive-data")]
public async Task<ActionResult<SensitiveData>> GetSensitiveData()
{
    var userId = GetCurrentUserId();
    var clientIP = HttpContext.Connection.RemoteIpAddress?.ToString();
    
    // Check if access is from unusual location
    var geoAnalysis = await _behaviorService.AnalyzeGeographicPatternAsync(userId, clientIP);
    
    if (geoAnalysis.IsAnomalous)
    {
        // Log security event
        await _securityService.LogSecurityEventAsync(new SecurityEvent
        {
            EventType = "GeographicAnomaly",
            UserId = userId,
            ClientIP = clientIP,
            Description = $"Access from unusual location: {geoAnalysis.CurrentLocation}",
            ThreatScore = geoAnalysis.AnomalyScore
        });
        
        if (geoAnalysis.AnomalyScore > 80)
        {
            return Forbid("Access denied due to geographic anomaly");
        }
    }
    
    var data = await _dataService.GetSensitiveDataAsync(userId);
    return Ok(data);
}
```

## Common Use Cases

### E-commerce IDOR Protection

```csharp
[ApiController]
[Route("api/[controller]")]
public class ECommerceController : ControllerBase
{
    [HttpGet("orders/{orderId}")]
    [ParameterSecurity("orderId", RequireOwnership = true)]
    public async Task<ActionResult<OrderDetails>> GetOrder(int orderId)
    {
        // Prevents users from accessing other users' orders
        var order = await _orderService.GetOrderDetailsAsync(orderId);
        return Ok(order);
    }
    
    [HttpGet("cart/{cartId}/items")]
    [ParameterSecurity("cartId", RequireOwnership = true)]
    public async Task<ActionResult<List<CartItem>>> GetCartItems(int cartId)
    {
        // Prevents cart enumeration attacks
        var items = await _cartService.GetCartItemsAsync(cartId);
        return Ok(items);
    }
    
    [HttpPost("payment")]
    [RateLimit(RequestsPerMinute = 10)]
    public async Task<ActionResult<PaymentResult>> ProcessPayment([FromBody] PaymentRequest request)
    {
        // Rate limit payment attempts to prevent abuse
        var result = await _paymentService.ProcessPaymentAsync(request);
        return Ok(result);
    }
}
```

### Content Management System Protection

```csharp
[ApiController]
[Route("api/[controller]")]
public class CMSController : ControllerBase
{
    [HttpPost("content")]
    public async Task<ActionResult<Content>> CreateContent([FromBody] CreateContentRequest request)
    {
        // SecurityFramework automatically scans for:
        // - XSS in content
        // - Script injection
        // - HTML manipulation
        
        var content = await _contentService.CreateAsync(request);
        return Ok(content);
    }
    
    [HttpGet("files/{fileId}")]
    [ParameterSecurity("fileId", RequireOwnership = true, AllowAdminOverride = true)]
    public async Task<ActionResult<FileInfo>> GetFile(int fileId)
    {
        // Prevents unauthorized file access
        // Allows admin override for management purposes
        
        var file = await _fileService.GetFileInfoAsync(fileId);
        return Ok(file);
    }
}
```

### API Security

```csharp
[ApiController]
[Route("api/v1/[controller]")]
public class SecureAPIController : ControllerBase
{
    [HttpGet("users/{userId}/data")]
    [ParameterSecurity("userId", RequireOwnership = true)]
    [RateLimit(RequestsPerMinute = 100)]
    public async Task<ActionResult<UserData>> GetUserData(int userId)
    {
        // Combined protection:
        // - IDOR prevention
        // - Rate limiting
        // - Automatic pattern scanning
        
        var data = await _userDataService.GetDataAsync(userId);
        return Ok(data);
    }
    
    [HttpPost("search")]
    [RateLimit(RequestsPerMinute = 50)]
    public async Task<ActionResult<SearchResults>> Search([FromBody] SearchRequest request)
    {
        // Protects against:
        // - SQL injection in search terms
        // - NoSQL injection
        // - LDAP injection
        // - Search abuse
        
        var results = await _searchService.SearchAsync(request.Query);
        return Ok(results);
    }
}
```

## Best Practices

### 1. Configuration Management

```csharp
// Use environment-specific configurations
public class SecurityConfigurationHelper
{
    public static void ConfigureSecurityFramework(
        IServiceCollection services, 
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        services.AddSecurityFramework(configuration);
        
        if (environment.IsDevelopment())
        {
            // Relaxed settings for development
            services.Configure<SecurityFrameworkOptions>(options =>
            {
                options.DefaultThreatThreshold = 30;
                options.IPSecurity.AutoBlockEnabled = false;
                options.ParameterSecurity.AutoBlockOnHighRisk = false;
            });
        }
        else if (environment.IsProduction())
        {
            // Strict settings for production
            services.Configure<SecurityFrameworkOptions>(options =>
            {
                options.DefaultThreatThreshold = 70;
                options.IPSecurity.AutoBlockEnabled = true;
                options.ParameterSecurity.AutoBlockOnHighRisk = true;
            });
        }
    }
}
```

### 2. Error Handling

```csharp
public class SecurityExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (exception is SecurityFrameworkException securityEx)
        {
            // Log security exception without exposing details
            var logger = httpContext.RequestServices.GetRequiredService<ILogger<SecurityExceptionHandler>>();
            logger.LogWarning(securityEx, "Security framework exception: {Message}", securityEx.Message);
            
            httpContext.Response.StatusCode = securityEx.StatusCode;
            await httpContext.Response.WriteAsJsonAsync(new
            {
                error = "Security validation failed",
                requestId = httpContext.TraceIdentifier
            }, cancellationToken);
            
            return true;
        }
        
        return false;
    }
}
```

### 3. Monitoring and Alerting

```csharp
public class SecurityEventHandler : ISecurityEventHandler
{
    private readonly ILogger<SecurityEventHandler> _logger;
    private readonly INotificationService _notificationService;
    
    public async Task HandleSecurityEventAsync(SecurityEvent securityEvent)
    {
        // Log all security events
        _logger.LogWarning("Security event: {EventType} from {ClientIP} with score {ThreatScore}",
            securityEvent.EventType, securityEvent.ClientIP, securityEvent.ThreatScore);
            
        // Send critical alerts
        if (securityEvent.ThreatScore > 80)
        {
            await _notificationService.SendCriticalAlertAsync(
                $"Critical security threat detected from {securityEvent.ClientIP}",
                securityEvent);
        }
    }
}
```

### 4. Testing

```csharp
public class SecurityIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    
    [Fact]
    public async Task API_WithSQLInjection_ShouldBlock()
    {
        // Arrange
        var client = _factory.CreateClient();
        var maliciousPayload = "'; DROP TABLE Users; --";
        
        // Act
        var response = await client.GetAsync($"/api/users/search?q={maliciousPayload}");
        
        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
    
    [Fact]
    public async Task API_WithIDORAttempt_ShouldBlock()
    {
        // Arrange
        var client = _factory.CreateClient();
        // Assume user 1 is trying to access user 2's data
        
        // Act
        var response = await client.GetAsync("/api/users/2/profile");
        
        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
```

## Troubleshooting

### Common Issues

#### 1. High False Positive Rate

```csharp
// Adjust threat thresholds
{
  "SecurityFramework": {
    "DefaultThreatThreshold": 70,  // Increase from default 50
    "IPSecurity": {
      "AutoBlockThreshold": 85     // Increase from default 75
    }
  }
}
```

#### 2. Performance Issues

```csharp
// Enable caching and optimize patterns
{
  "SecurityFramework": {
    "Patterns": {
      "CompilePatterns": true,
      "MatchTimeout": "00:00:00.050"  // 50ms timeout
    },
    "Performance": {
      "EnableCaching": true,
      "MaxConcurrentRequests": 5000
    }
  }
}
```

#### 3. Database Connection Issues

```csharp
// Fallback to in-memory only
{
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": false  // Disable if DB issues
  }
}
```

### Debugging

```csharp
// Enable detailed logging
{
  "Logging": {
    "LogLevel": {
      "SecurityFramework": "Debug",
      "SecurityFramework.Middleware": "Information"
    }
  }
}
```

### Health Checks

```csharp
// Add health checks
builder.Services.AddHealthChecks()
    .AddCheck<SecurityFrameworkHealthCheck>("security-framework");

app.MapHealthChecks("/health");
```

### Metrics and Monitoring

```csharp
// Access security metrics
[HttpGet("security/metrics")]
public async Task<ActionResult<SecurityMetrics>> GetSecurityMetrics()
{
    var metrics = await _securityService.GetMetricsAsync(TimeSpan.FromHours(24));
    return Ok(new
    {
        ThreatsDetected = metrics.ThreatsDetected,
        RequestsBlocked = metrics.RequestsBlocked,
        AverageProcessingTime = metrics.AverageProcessingTime,
        TopThreatTypes = metrics.TopThreatTypes
    });
}
```

---

This guide provides practical examples for implementing the SecurityFramework in real-world applications. Start with the quick start guide and gradually implement additional security features based on your specific requirements.