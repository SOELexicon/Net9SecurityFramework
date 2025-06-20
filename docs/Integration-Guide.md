# SecurityFramework Integration Guide

## Overview

This guide provides comprehensive instructions for integrating the SecurityFramework into ASP.NET Core applications. Whether you're building a simple API or a complex enterprise application, this guide covers all integration patterns and best practices.

## Table of Contents

1. [Quick Start Integration](#quick-start-integration)
2. [Project Setup](#project-setup)
3. [Service Registration](#service-registration)
4. [Middleware Configuration](#middleware-configuration)
5. [Controller Integration](#controller-integration)
6. [Authentication Integration](#authentication-integration)
7. [Advanced Integration Patterns](#advanced-integration-patterns)
8. [Real-Time Features Integration](#real-time-features-integration)
9. [Testing Integration](#testing-integration)
10. [Migration Strategies](#migration-strategies)
11. [Troubleshooting](#troubleshooting)

## Quick Start Integration

### Minimal Integration (5 minutes)

For a basic setup with default security features:

```csharp
// Program.cs (.NET 9+)
using SecurityFramework.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddSecurityFramework(); // Add with defaults

var app = builder.Build();

// Configure middleware pipeline
app.UseSecurityFramework(); // Must be early in pipeline
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

### Basic Configuration

```json
// appsettings.json
{
  "SecurityFramework": {
    "EnableInMemoryStorage": true,
    "DefaultThreatThreshold": 50,
    "IPSecurity": {
      "EnableBlocklist": true,
      "AutoBlockEnabled": false
    },
    "ParameterSecurity": {
      "EnableParameterJackingDetection": true,
      "DetectIDManipulation": true
    }
  }
}
```

This provides immediate protection against:
- Basic IP-based threats
- Parameter manipulation attempts
- Rate limiting violations
- Common attack patterns

## Project Setup

### Package Installation

```xml
<!-- SecurityFramework.csproj or in PackageReference -->
<PackageReference Include="SecurityFramework.Core" Version="1.0.0" />
<PackageReference Include="SecurityFramework.AspNetCore" Version="1.0.0" />

<!-- Optional packages -->
<PackageReference Include="SecurityFramework.RealTime" Version="1.0.0" Condition="'$(EnableRealTime)' == 'true'" />
<PackageReference Include="SecurityFramework.ML" Version="1.0.0" Condition="'$(EnableML)' == 'true'" />
```

### Project Structure Integration

```
YourProject/
├── Controllers/
│   ├── SecurityController.cs     # Optional: Security management API
│   └── ApiControllers/           # Your protected controllers
├── Security/
│   ├── Patterns/                 # Custom threat patterns
│   │   ├── custom-patterns.json
│   │   └── company-rules.json
│   ├── Policies/                 # Custom security policies
│   │   └── SecurityPolicies.cs
│   └── Validators/               # Custom parameter validators
│       └── CustomValidators.cs
├── Configuration/
│   ├── SecurityConfiguration.cs  # Security setup
│   └── SecurityPolicies.cs      # Authorization policies
└── appsettings.json              # Configuration
```

### Dependency Injection Setup

```csharp
// SecurityConfiguration.cs
using SecurityFramework.Core.Extensions;
using SecurityFramework.Core.Abstractions;

public static class SecurityConfiguration
{
    public static IServiceCollection AddApplicationSecurity(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        // Core SecurityFramework
        services.AddSecurityFramework(options =>
        {
            configuration.GetSection("SecurityFramework").Bind(options);
        });

        // Optional: Add real-time features
        if (configuration.GetValue<bool>("SecurityFramework:RealTimeMonitoring:Enabled"))
        {
            services.AddSecurityFrameworkRealTime(options =>
            {
                configuration.GetSection("SecurityFramework:RealTimeMonitoring").Bind(options);
            });
        }

        // Optional: Add machine learning
        if (configuration.GetValue<bool>("SecurityFramework:MachineLearning:Enabled"))
        {
            services.AddSecurityFrameworkML(options =>
            {
                configuration.GetSection("SecurityFramework:MachineLearning").Bind(options);
            });
        }

        // Custom security services
        services.AddScoped<ICustomSecurityValidator, CustomSecurityValidator>();
        services.AddScoped<ICompanySecurityPolicy, CompanySecurityPolicy>();

        // Health checks
        services.AddHealthChecks()
            .AddCheck<SecurityFrameworkHealthCheck>("security_framework")
            .AddCheck<CustomSecurityHealthCheck>("custom_security");

        return services;
    }
}
```

## Service Registration

### Basic Service Registration

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Register SecurityFramework with configuration
builder.Services.AddSecurityFramework(options =>
{
    // Core configuration
    options.EnableInMemoryStorage = true;
    options.EnableSQLitePersistence = true;
    options.SQLiteConnectionString = builder.Configuration.GetConnectionString("SecurityDB");
    options.DefaultThreatThreshold = 50;
    options.DataRetentionDays = 90;

    // IP Security configuration
    options.IPSecurity.EnableBlocklist = true;
    options.IPSecurity.AutoBlockEnabled = true;
    options.IPSecurity.AutoBlockThreshold = 75;
    options.IPSecurity.AllowPrivateNetworks = true;

    // Parameter Security configuration
    options.ParameterSecurity.EnableParameterJackingDetection = true;
    options.ParameterSecurity.DetectIDManipulation = true;
    options.ParameterSecurity.DetectSequentialAccess = true;
    options.ParameterSecurity.SequentialAccessThreshold = 5;
    options.ParameterSecurity.AutoBlockOnHighRisk = true;

    // Pattern configuration
    options.Patterns.EnablePatternMatching = true;
    options.Patterns.PatternDirectory = "Security/Patterns";
    options.Patterns.AutoReload = true;

    // Performance configuration
    options.Performance.EnableCaching = true;
    options.Performance.MaxConcurrentRequests = 10000;
    options.Performance.EnableMetrics = true;

    // Notification configuration
    options.Notifications.EnableWebhooks = true;
    options.Notifications.CriticalThreshold = 75;
});
```

### Advanced Service Registration with Custom Services

```csharp
// Advanced configuration with custom implementations
builder.Services.AddSecurityFramework(options =>
{
    // Load from configuration
    builder.Configuration.GetSection("SecurityFramework").Bind(options);
})
.AddCustomScoringEngine<AdvancedScoringEngine>()
.AddCustomPatternMatcher<RegexPatternMatcher>()
.AddCustomThreatDetector<MLThreatDetector>()
.AddCustomBlockingService<GeoBlockingService>();

// Custom security validators
builder.Services.AddScoped<IParameterValidator, CustomParameterValidator>();
builder.Services.AddScoped<IIPValidator, CompanyIPValidator>();
builder.Services.AddScoped<IThreatAnalyzer, AdvancedThreatAnalyzer>();

// External integrations
builder.Services.AddHttpClient<IExternalThreatFeed, SpamhausThreatFeed>();
builder.Services.AddHttpClient<IGeoIPService, MaxMindGeoIPService>();

// Background services
builder.Services.AddHostedService<SecurityDataPersistenceService>();
builder.Services.AddHostedService<ThreatIntelligenceUpdateService>();
builder.Services.AddHostedService<SecurityMetricsCollectionService>();
```

### Configuration Validation Setup

```csharp
// Add configuration validation
builder.Services.AddOptions<SecurityFrameworkOptions>()
    .Bind(builder.Configuration.GetSection("SecurityFramework"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Custom validation
builder.Services.AddSingleton<IValidateOptions<SecurityFrameworkOptions>, 
    CustomSecurityFrameworkOptionsValidator>();

// Configuration monitoring
builder.Services.Configure<SecurityFrameworkOptions>(
    builder.Configuration.GetSection("SecurityFramework"));
```

## Middleware Configuration

### Basic Middleware Pipeline

```csharp
var app = builder.Build();

// Security middleware must be early in pipeline
app.UseSecurityFramework(options =>
{
    options.EnableDetailedLogging = app.Environment.IsDevelopment();
    options.BypassPaths = new[] { "/health", "/metrics", "/swagger" };
    options.TrustedProxies = new[] { "10.0.0.0/8", "172.16.0.0/12" };
});

// Standard ASP.NET Core middleware
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Authentication/Authorization
app.UseAuthentication();
app.UseAuthorization();

// Application middleware
app.MapControllers();
app.MapHealthChecks("/health");
```

### Advanced Middleware Configuration

```csharp
var app = builder.Build();

// Configure security headers first
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

// HTTPS redirection
app.UseHttpsRedirection();

// Security Framework middleware with detailed configuration
app.UseSecurityFramework(options =>
{
    // Request processing options
    options.EnableDetailedLogging = app.Environment.IsDevelopment();
    options.LogSensitiveData = false;
    options.IncludeRequestBodies = false;
    
    // Path exclusions
    options.BypassPaths = new[]
    {
        "/health", "/metrics", "/swagger", "/favicon.ico",
        "/css", "/js", "/images", "/fonts"
    };
    
    // Trusted networks
    options.TrustedProxies = new[]
    {
        "10.0.0.0/8",      // Private network
        "172.16.0.0/12",   // Private network
        "192.168.0.0/16",  // Private network
        "127.0.0.1/8"      // Localhost
    };
    
    // Load balancer configuration
    options.UseForwardedHeaders = true;
    options.ForwardedHeadersOptions = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
        KnownProxies = { IPAddress.Parse("10.0.0.100") }
    };
    
    // Custom error handling
    options.CustomErrorHandler = async (context, exception) =>
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError(exception, "Security middleware error");
        
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Security processing error");
    };
});

// CORS (if needed)
app.UseCors("SecurityFrameworkPolicy");

// Static files with security headers
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        ctx.Context.Response.Headers.Add("Cache-Control", "public,max-age=3600");
        ctx.Context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    }
});

app.UseRouting();

// Rate limiting (additional layer)
app.UseRateLimiter();

// Authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

// Real-time features (if enabled)
var realTimeOptions = app.Services.GetService<IOptions<RealTimeOptions>>()?.Value;
if (realTimeOptions?.Enabled == true)
{
    app.UseSecurityFrameworkRealTime();
}

// Application endpoints
app.MapControllers();
app.MapHealthChecks("/health");
app.MapMetrics("/metrics"); // If using OpenTelemetry

app.Run();
```

### Conditional Middleware Registration

```csharp
// Environment-specific middleware
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
    
    // Relaxed security for development
    app.UseSecurityFramework(options =>
    {
        options.EnableDetailedLogging = true;
        options.LogSensitiveData = true;
        options.BypassPaths = new[] { "/swagger", "/swagger/v1/swagger.json" };
    });
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    
    // Production security settings
    app.UseSecurityFramework(options =>
    {
        options.EnableDetailedLogging = false;
        options.LogSensitiveData = false;
        options.StrictMode = true;
    });
}
```

## Controller Integration

### Basic Controller Protection

```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ISecurityService _securityService;

    public UsersController(IUserService userService, ISecurityService securityService)
    {
        _userService = userService;
        _securityService = securityService;
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<User>> GetUser(
        [FromRoute] 
        [SecureParameter(ParameterName = "id", Type = ParameterType.UserContext)]
        string id)
    {
        // Parameter validation happens automatically via SecureParameter attribute
        var user = await _userService.GetUserAsync(id);
        return Ok(user);
    }

    [HttpGet]
    [RateLimit(RequestsPerMinute = 100)]
    public async Task<ActionResult<IEnumerable<User>>> GetUsers()
    {
        var users = await _userService.GetUsersAsync();
        return Ok(users);
    }
}
```

### Advanced Controller Security

```csharp
[ApiController]
[Route("api/[controller]")]
[IPRestriction(MaxThreatScore = 25)] // Controller-level IP restrictions
public class OrdersController : ControllerBase
{
    private readonly IOrderService _orderService;
    private readonly IParameterSecurityService _parameterSecurity;
    private readonly ILogger<OrdersController> _logger;

    public OrdersController(
        IOrderService orderService, 
        IParameterSecurityService parameterSecurity,
        ILogger<OrdersController> logger)
    {
        _orderService = orderService;
        _parameterSecurity = parameterSecurity;
        _logger = logger;
    }

    [HttpGet("{orderId}")]
    [RateLimit(RequestsPerMinute = 60, PerUser = true)]
    public async Task<ActionResult<Order>> GetOrder(
        [FromRoute] 
        [SecureParameter(
            ParameterName = "orderId", 
            Type = ParameterType.UserContext,
            RequireOwnership = true,
            PreventSequentialAccess = true)]
        string orderId)
    {
        try
        {
            // Additional manual security check
            var clientIP = HttpContext.Connection.RemoteIpAddress?.ToString();
            var assessment = await _securityService.AssessIPAsync(clientIP!);
            
            if (assessment.ThreatLevel >= ThreatLevel.High)
            {
                _logger.LogWarning("High threat level access attempt for order {OrderId} from IP {IP}", 
                    orderId, clientIP);
                return StatusCode(429, "Request rate limited due to security concerns");
            }

            // Validate parameter access manually (additional layer)
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isValidAccess = await _parameterSecurity.ValidateParameterAccessAsync(
                userId, "orderId", orderId, new RequestContext
                {
                    IPAddress = clientIP,
                    UserAgent = Request.Headers.UserAgent,
                    RequestPath = Request.Path,
                    Timestamp = DateTime.UtcNow
                });

            if (!isValidAccess)
            {
                _logger.LogWarning("Unauthorized parameter access attempt: User {UserId} trying to access Order {OrderId}", 
                    userId, orderId);
                return Forbid("Access denied to requested resource");
            }

            var order = await _orderService.GetOrderAsync(orderId);
            if (order == null)
            {
                return NotFound();
            }

            return Ok(order);
        }
        catch (SecurityValidationException ex)
        {
            _logger.LogWarning(ex, "Security validation failed for order access");
            return BadRequest("Invalid request parameters");
        }
        catch (RateLimitException ex)
        {
            _logger.LogInformation("Rate limit exceeded for order access");
            return StatusCode(429, new { 
                message = "Rate limit exceeded", 
                retryAfter = ex.RetryAfterSeconds 
            });
        }
    }

    [HttpPost]
    [RateLimit(RequestsPerMinute = 10, PerUser = true)]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult<Order>> CreateOrder([FromBody] CreateOrderRequest request)
    {
        // Validate request against patterns
        var patternMatches = await _patternService.MatchPatternsAsync(
            JsonSerializer.Serialize(request));

        if (patternMatches.Any(m => m.ThreatMultiplier > 50))
        {
            _logger.LogWarning("Suspicious order creation attempt detected");
            return BadRequest("Invalid order data");
        }

        var order = await _orderService.CreateOrderAsync(request);
        return CreatedAtAction(nameof(GetOrder), new { orderId = order.Id }, order);
    }

    [HttpPut("{orderId}")]
    [Authorize(Roles = "User,Admin")]
    public async Task<ActionResult> UpdateOrder(
        [FromRoute]
        [SecureParameter(ParameterName = "orderId", RequireOwnership = true)]
        string orderId,
        [FromBody] UpdateOrderRequest request)
    {
        // Check if this looks like a parameter manipulation attempt
        var assessment = await _parameterSecurity.AssessParameterRequestAsync(HttpContext);
        
        if (assessment.RiskLevel >= JackingRiskLevel.High)
        {
            _logger.LogWarning("High-risk parameter manipulation detected for order update: {Assessment}", 
                JsonSerializer.Serialize(assessment));
            return StatusCode(403, "Access denied due to security policy");
        }

        await _orderService.UpdateOrderAsync(orderId, request);
        return NoContent();
    }
}
```

### Global Action Filters

```csharp
public class SecurityActionFilter : ActionFilterAttribute
{
    private readonly ISecurityService _securityService;
    private readonly ILogger<SecurityActionFilter> _logger;

    public SecurityActionFilter(ISecurityService securityService, ILogger<SecurityActionFilter> logger)
    {
        _securityService = securityService;
        _logger = logger;
    }

    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var clientIP = context.HttpContext.Connection.RemoteIpAddress?.ToString();
        
        if (!string.IsNullOrEmpty(clientIP))
        {
            // Assess IP threat level before action execution
            var assessment = await _securityService.AssessIPAsync(clientIP);
            
            if (assessment.ThreatLevel >= ThreatLevel.Critical)
            {
                _logger.LogWarning("Blocking critical threat level request from IP {IP}", clientIP);
                context.Result = new StatusCodeResult(403);
                return;
            }
            
            // Add threat info to request context
            context.HttpContext.Items["ThreatAssessment"] = assessment;
        }

        await next();
    }
}

// Register globally
builder.Services.AddControllers(options =>
{
    options.Filters.Add<SecurityActionFilter>();
});
```

## Authentication Integration

### JWT Authentication Integration

```csharp
public static class AuthenticationConfiguration
{
    public static IServiceCollection AddApplicationAuthentication(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        // JWT configuration
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    ValidAudience = configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!))
                };

                // Integration with SecurityFramework
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var securityService = context.HttpContext.RequestServices
                            .GetRequiredService<ISecurityService>();
                        var clientIP = context.HttpContext.Connection.RemoteIpAddress?.ToString();
                        
                        if (!string.IsNullOrEmpty(clientIP))
                        {
                            var assessment = await securityService.AssessIPAsync(clientIP);
                            if (assessment.ThreatLevel >= ThreatLevel.High)
                            {
                                context.Fail("High threat level detected");
                                return;
                            }
                        }
                    },
                    
                    OnAuthenticationFailed = async context =>
                    {
                        var securityService = context.HttpContext.RequestServices
                            .GetRequiredService<ISecurityService>();
                        var clientIP = context.HttpContext.Connection.RemoteIpAddress?.ToString();
                        
                        if (!string.IsNullOrEmpty(clientIP))
                        {
                            await securityService.IncreaseThreatScoreAsync(
                                clientIP, 10, "JWT authentication failed");
                        }
                    }
                };
            });

        // Authorization policies
        services.AddAuthorization(options =>
        {
            options.AddPolicy("LowThreatOnly", policy =>
                policy.Requirements.Add(new ThreatLevelRequirement(ThreatLevel.Medium)));
            
            options.AddPolicy("AdminOnly", policy =>
                policy.RequireRole("Admin")
                       .Requirements.Add(new ThreatLevelRequirement(ThreatLevel.Low)));
        });

        // Custom authorization handlers
        services.AddSingleton<IAuthorizationHandler, ThreatLevelAuthorizationHandler>();

        return services;
    }
}
```

### Custom Authorization Requirements

```csharp
public class ThreatLevelRequirement : IAuthorizationRequirement
{
    public ThreatLevel MaxThreatLevel { get; }

    public ThreatLevelRequirement(ThreatLevel maxThreatLevel)
    {
        MaxThreatLevel = maxThreatLevel;
    }
}

public class ThreatLevelAuthorizationHandler : AuthorizationHandler<ThreatLevelRequirement>
{
    private readonly ISecurityService _securityService;
    private readonly ILogger<ThreatLevelAuthorizationHandler> _logger;

    public ThreatLevelAuthorizationHandler(
        ISecurityService securityService, 
        ILogger<ThreatLevelAuthorizationHandler> logger)
    {
        _securityService = securityService;
        _logger = logger;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ThreatLevelRequirement requirement)
    {
        if (context.Resource is HttpContext httpContext)
        {
            var clientIP = httpContext.Connection.RemoteIpAddress?.ToString();
            
            if (string.IsNullOrEmpty(clientIP))
            {
                context.Fail();
                return;
            }

            var assessment = await _securityService.AssessIPAsync(clientIP);
            
            if (assessment.ThreatLevel <= requirement.MaxThreatLevel)
            {
                context.Succeed(requirement);
                _logger.LogDebug("Authorization succeeded for IP {IP} with threat level {ThreatLevel}", 
                    clientIP, assessment.ThreatLevel);
            }
            else
            {
                context.Fail();
                _logger.LogWarning("Authorization failed for IP {IP} due to high threat level {ThreatLevel}", 
                    clientIP, assessment.ThreatLevel);
            }
        }
    }
}
```

### Identity Integration

```csharp
public static class IdentityConfiguration
{
    public static IServiceCollection AddApplicationIdentity(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddDefaultIdentity<ApplicationUser>(options =>
        {
            // Password requirements
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = true;
            
            // Lockout settings
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>();

        // Configure cookie authentication to work with SecurityFramework
        services.ConfigureApplicationCookie(options =>
        {
            options.Events.OnValidatePrincipal = async context =>
            {
                var securityService = context.HttpContext.RequestServices
                    .GetRequiredService<ISecurityService>();
                var clientIP = context.HttpContext.Connection.RemoteIpAddress?.ToString();
                
                if (!string.IsNullOrEmpty(clientIP))
                {
                    var assessment = await securityService.AssessIPAsync(clientIP);
                    if (assessment.ThreatLevel >= ThreatLevel.Critical)
                    {
                        context.RejectPrincipal();
                        await context.HttpContext.SignOutAsync();
                    }
                }
            };
        });

        return services;
    }
}
```

## Advanced Integration Patterns

### Custom Security Validators

```csharp
public class CompanySecurityValidator : IParameterValidator
{
    private readonly IUserService _userService;
    private readonly ISecurityService _securityService;
    private readonly ILogger<CompanySecurityValidator> _logger;

    public CompanySecurityValidator(
        IUserService userService,
        ISecurityService securityService,
        ILogger<CompanySecurityValidator> logger)
    {
        _userService = userService;
        _securityService = securityService;
        _logger = logger;
    }

    public async Task<ValidationResult> ValidateParameterAsync(
        string userId, 
        string parameterName, 
        string parameterValue, 
        ValidationContext context)
    {
        try
        {
            // Company-specific validation logic
            switch (parameterName.ToLowerInvariant())
            {
                case "employee_id":
                    return await ValidateEmployeeIdAsync(userId, parameterValue, context);
                
                case "department_id":
                    return await ValidateDepartmentAccessAsync(userId, parameterValue, context);
                
                case "project_id":
                    return await ValidateProjectAccessAsync(userId, parameterValue, context);
                
                default:
                    return ValidationResult.Success;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating parameter {ParameterName} for user {UserId}", 
                parameterName, userId);
            return ValidationResult.Fail("Parameter validation failed");
        }
    }

    private async Task<ValidationResult> ValidateEmployeeIdAsync(
        string userId, 
        string employeeId, 
        ValidationContext context)
    {
        // Check if user can access this employee's data
        var currentUser = await _userService.GetUserAsync(userId);
        var targetEmployee = await _userService.GetEmployeeAsync(employeeId);

        if (targetEmployee == null)
        {
            return ValidationResult.Fail("Employee not found");
        }

        // Allow access if:
        // 1. User is accessing their own data
        // 2. User is a manager of the employee
        // 3. User has HR role
        if (currentUser.EmployeeId == employeeId ||
            currentUser.ManagedEmployees.Contains(employeeId) ||
            currentUser.Roles.Contains("HR"))
        {
            return ValidationResult.Success;
        }

        // Log unauthorized access attempt
        await _securityService.RecordIncidentAsync(new SecurityIncidentRequest
        {
            IPAddress = context.ClientIP,
            Type = IncidentType.ParameterJacking,
            Description = $"Unauthorized attempt to access employee {employeeId} by user {userId}",
            SeverityScore = 60,
            Metadata = new Dictionary<string, object>
            {
                ["ParameterName"] = "employee_id",
                ["ParameterValue"] = employeeId,
                ["RequestedBy"] = userId,
                ["UserAgent"] = context.UserAgent
            }
        });

        return ValidationResult.Fail("Access denied to employee data");
    }
}
```

### Event Handling Integration

```csharp
public class SecurityEventHandler : INotificationHandler<ThreatDetectedEvent>
{
    private readonly IEmailService _emailService;
    private readonly ISlackService _slackService;
    private readonly ILogger<SecurityEventHandler> _logger;
    private readonly SecurityFrameworkOptions _options;

    public SecurityEventHandler(
        IEmailService emailService,
        ISlackService slackService,
        ILogger<SecurityEventHandler> logger,
        IOptions<SecurityFrameworkOptions> options)
    {
        _emailService = emailService;
        _slackService = slackService;
        _logger = logger;
        _options = options.Value;
    }

    public async Task Handle(ThreatDetectedEvent notification, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogWarning("Threat detected: {ThreatLevel} from IP {IPAddress} - {Description}",
                notification.ThreatLevel, notification.IPAddress, notification.Description);

            // Send notifications based on threat level
            if (notification.ThreatLevel >= ThreatLevel.High)
            {
                await SendCriticalAlertAsync(notification);
            }
            else if (notification.ThreatLevel >= ThreatLevel.Medium)
            {
                await SendWarningAlertAsync(notification);
            }

            // Update external security systems
            await UpdateSIEMAsync(notification);
            await UpdateFirewallRulesAsync(notification);

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling threat detection event");
        }
    }

    private async Task SendCriticalAlertAsync(ThreatDetectedEvent evt)
    {
        // Send email to security team
        if (_options.Notifications.EnableEmail)
        {
            await _emailService.SendAsync(new EmailMessage
            {
                To = new[] { "security@company.com", "soc@company.com" },
                Subject = $"[CRITICAL] Security Threat Detected from {evt.IPAddress}",
                Body = $"""
                    Critical security threat detected:
                    
                    IP Address: {evt.IPAddress}
                    Threat Level: {evt.ThreatLevel}
                    Threat Score: {evt.ThreatScore}
                    Description: {evt.Description}
                    Timestamp: {evt.Timestamp:yyyy-MM-dd HH:mm:ss} UTC
                    Action Taken: {evt.ActionTaken}
                    
                    Pattern Matches:
                    {string.Join("\n", evt.PatternMatches.Select(m => $"- {m.PatternName}: {m.MatchedValue}"))}
                    
                    Risk Factors:
                    {string.Join("\n", evt.RiskFactors.Select(r => $"- {r}"))}
                    """
            });
        }

        // Send Slack notification
        await _slackService.SendMessageAsync(new SlackMessage
        {
            Channel = "#security-alerts",
            Text = $"🚨 CRITICAL: Security threat from {evt.IPAddress}",
            Attachments = new[]
            {
                new SlackAttachment
                {
                    Color = "danger",
                    Fields = new[]
                    {
                        new SlackField { Title = "IP Address", Value = evt.IPAddress, Short = true },
                        new SlackField { Title = "Threat Level", Value = evt.ThreatLevel.ToString(), Short = true },
                        new SlackField { Title = "Threat Score", Value = evt.ThreatScore.ToString("F1"), Short = true },
                        new SlackField { Title = "Action", Value = evt.ActionTaken.ToString(), Short = true },
                        new SlackField { Title = "Description", Value = evt.Description, Short = false }
                    }
                }
            }
        });
    }
}
```

### Background Service Integration

```csharp
public class SecurityMaintenanceService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SecurityMaintenanceService> _logger;
    private readonly SecurityFrameworkOptions _options;

    public SecurityMaintenanceService(
        IServiceProvider serviceProvider,
        ILogger<SecurityMaintenanceService> logger,
        IOptions<SecurityFrameworkOptions> options)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();
                var patternService = scope.ServiceProvider.GetRequiredService<IPatternService>();

                // Perform maintenance tasks
                await PerformDataCleanupAsync(securityService);
                await UpdateThreatIntelligenceAsync(securityService);
                await ReloadPatternsAsync(patternService);
                await PersistDataAsync(securityService);
                await GenerateSecurityReportsAsync(securityService);

                // Wait before next cycle
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in security maintenance service");
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
        }
    }

    private async Task PerformDataCleanupAsync(ISecurityService securityService)
    {
        _logger.LogInformation("Starting security data cleanup");
        
        // Clean up old data based on retention policy
        var cutoffDate = DateTime.UtcNow.AddDays(-_options.DataRetentionDays);
        await securityService.CleanupOldDataAsync(cutoffDate);
        
        _logger.LogInformation("Security data cleanup completed");
    }

    private async Task UpdateThreatIntelligenceAsync(ISecurityService securityService)
    {
        _logger.LogInformation("Updating threat intelligence");
        
        // Update external threat feeds
        await securityService.UpdateExternalThreatsAsync();
        
        _logger.LogInformation("Threat intelligence update completed");
    }
}
```

## Real-Time Features Integration

### SignalR Hub Integration

```csharp
[Authorize]
public class SecurityDashboardHub : Hub<ISecurityDashboardClient>
{
    private readonly ISecurityService _securityService;
    private readonly IConnectionManager _connectionManager;
    private readonly ILogger<SecurityDashboardHub> _logger;

    public SecurityDashboardHub(
        ISecurityService securityService,
        IConnectionManager connectionManager,
        ILogger<SecurityDashboardHub> logger)
    {
        _securityService = securityService;
        _connectionManager = connectionManager;
        _logger = logger;
    }

    public override async Task OnConnectedAsync()
    {
        var clientIP = GetClientIP();
        var assessment = await _securityService.AssessIPAsync(clientIP);
        
        if (assessment.ThreatLevel > ThreatLevel.Medium)
        {
            _logger.LogWarning("High threat level connection attempt from {IP}", clientIP);
            Context.Abort();
            return;
        }

        await _connectionManager.AddConnectionAsync(Context.ConnectionId, clientIP);
        await Groups.AddToGroupAsync(Context.ConnectionId, "SecurityDashboard");
        
        // Send initial data
        await Clients.Caller.OnConnected(new ConnectionInfo
        {
            ConnectionId = Context.ConnectionId,
            ConnectedAt = DateTime.UtcNow,
            IPAddress = clientIP
        });

        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await _connectionManager.RemoveConnectionAsync(Context.ConnectionId);
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, "SecurityDashboard");
        await base.OnDisconnectedAsync(exception);
    }

    public async Task SubscribeToThreatUpdates()
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, "ThreatUpdates");
    }

    public async Task GetCurrentThreats()
    {
        var threats = await _securityService.GetActiveThreatsAsync();
        await Clients.Caller.OnThreatsUpdate(threats);
    }

    public async Task GetIPDetails(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out _))
        {
            await Clients.Caller.OnError("Invalid IP address format");
            return;
        }

        var details = await _securityService.GetIPHistoryAsync(ipAddress);
        await Clients.Caller.OnIPDetails(details);
    }

    private string GetClientIP()
    {
        var httpContext = Context.GetHttpContext();
        return httpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

public interface ISecurityDashboardClient
{
    Task OnConnected(ConnectionInfo info);
    Task OnThreatDetected(ThreatDetectedEvent threat);
    Task OnIPBlocked(IPBlockedEvent blockEvent);
    Task OnThreatsUpdate(IEnumerable<ActiveThreat> threats);
    Task OnIPDetails(IPHistory details);
    Task OnMetricsUpdate(SecurityMetrics metrics);
    Task OnError(string message);
}
```

### Real-Time Event Broadcasting

```csharp
public class RealTimeSecurityService : ISecurityEventBroadcaster
{
    private readonly IHubContext<SecurityDashboardHub, ISecurityDashboardClient> _hubContext;
    private readonly ILogger<RealTimeSecurityService> _logger;

    public RealTimeSecurityService(
        IHubContext<SecurityDashboardHub, ISecurityDashboardClient> hubContext,
        ILogger<RealTimeSecurityService> logger)
    {
        _hubContext = hubContext;
        _logger = logger;
    }

    public async Task BroadcastThreatDetectedAsync(ThreatDetectedEvent threatEvent)
    {
        try
        {
            await _hubContext.Clients.Group("ThreatUpdates")
                .OnThreatDetected(threatEvent);
            
            // Send critical threats to all dashboard users
            if (threatEvent.ThreatLevel >= ThreatLevel.Critical)
            {
                await _hubContext.Clients.Group("SecurityDashboard")
                    .OnThreatDetected(threatEvent);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error broadcasting threat detection event");
        }
    }

    public async Task BroadcastIPBlockedAsync(IPBlockedEvent blockEvent)
    {
        try
        {
            await _hubContext.Clients.Group("SecurityDashboard")
                .OnIPBlocked(blockEvent);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error broadcasting IP blocked event");
        }
    }

    public async Task BroadcastMetricsAsync(SecurityMetrics metrics)
    {
        try
        {
            await _hubContext.Clients.Group("SecurityDashboard")
                .OnMetricsUpdate(metrics);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error broadcasting security metrics");
        }
    }
}
```

## Testing Integration

### Unit Testing Setup

```csharp
public class SecurityServiceTests
{
    private readonly Mock<IIPRepository> _mockIPRepository;
    private readonly Mock<IPatternService> _mockPatternService;
    private readonly Mock<IScoringEngine> _mockScoringEngine;
    private readonly Mock<ILogger<SecurityService>> _mockLogger;
    private readonly IOptions<SecurityFrameworkOptions> _options;
    private readonly SecurityService _securityService;

    public SecurityServiceTests()
    {
        _mockIPRepository = new Mock<IIPRepository>();
        _mockPatternService = new Mock<IPatternService>();
        _mockScoringEngine = new Mock<IScoringEngine>();
        _mockLogger = new Mock<ILogger<SecurityService>>();
        
        _options = Options.Create(new SecurityFrameworkOptions
        {
            DefaultThreatThreshold = 50,
            EnableInMemoryStorage = true
        });

        _securityService = new SecurityService(
            _mockIPRepository.Object,
            _mockPatternService.Object,
            _mockScoringEngine.Object,
            _options,
            _mockLogger.Object);
    }

    [Fact]
    public async Task AssessIPAsync_NewIP_ReturnsLowThreatLevel()
    {
        // Arrange
        var ipAddress = "192.168.1.100";
        _mockIPRepository.Setup(r => r.GetByIPAsync(ipAddress))
            .ReturnsAsync((IPRecord?)null);
        
        _mockScoringEngine.Setup(s => s.CalculateThreatScoreAsync(ipAddress, It.IsAny<ScoringContext>()))
            .ReturnsAsync(new ScoringResult { ThreatScore = 10, TrustScore = 50 });

        // Act
        var result = await _securityService.AssessIPAsync(ipAddress);

        // Assert
        Assert.Equal(ThreatLevel.Low, result.ThreatLevel);
        Assert.Equal(SecurityAction.Allow, result.RecommendedAction);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public async Task AssessIPAsync_HighThreatIP_ReturnsHighThreatLevel()
    {
        // Arrange
        var ipAddress = "10.0.0.1";
        var ipRecord = new IPRecord
        {
            IPAddress = ipAddress,
            ThreatScore = 80,
            TotalRequests = 100,
            IsBlocked = false
        };

        _mockIPRepository.Setup(r => r.GetByIPAsync(ipAddress))
            .ReturnsAsync(ipRecord);
        
        _mockScoringEngine.Setup(s => s.CalculateThreatScoreAsync(ipAddress, It.IsAny<ScoringContext>()))
            .ReturnsAsync(new ScoringResult { ThreatScore = 80, TrustScore = 20 });

        // Act
        var result = await _securityService.AssessIPAsync(ipAddress);

        // Assert
        Assert.Equal(ThreatLevel.High, result.ThreatLevel);
        Assert.Equal(SecurityAction.Block, result.RecommendedAction);
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
                // Override configuration for testing
                services.Configure<SecurityFrameworkOptions>(options =>
                {
                    options.EnableInMemoryStorage = true;
                    options.EnableSQLitePersistence = false;
                    options.DefaultThreatThreshold = 25; // Lower threshold for testing
                });
            });
        });
        
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task SecurityMiddleware_BlocksHighThreatRequests()
    {
        // Arrange - Create a high threat scenario
        var suspiciousUserAgent = "' OR 1=1 --";
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/users");
        request.Headers.Add("User-Agent", suspiciousUserAgent);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ParameterSecurity_DetectsIDManipulation()
    {
        // Arrange
        var token = await GetAuthTokenAsync("user123");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act - Try to access another user's data
        var response = await _client.GetAsync("/api/users/user456/orders");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task RateLimit_EnforcesLimits()
    {
        // Arrange
        var requests = new List<Task<HttpResponseMessage>>();

        // Act - Send many requests quickly
        for (int i = 0; i < 100; i++)
        {
            requests.Add(_client.GetAsync("/api/users"));
        }

        var responses = await Task.WhenAll(requests);

        // Assert
        Assert.Contains(responses, r => r.StatusCode == HttpStatusCode.TooManyRequests);
    }

    private async Task<string> GetAuthTokenAsync(string userId)
    {
        var loginRequest = new
        {
            UserId = userId,
            Password = "TestPassword123!"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
        return result?.Token ?? throw new InvalidOperationException("Failed to get auth token");
    }
}
```

### Load Testing Integration

```csharp
public class SecurityPerformanceTests
{
    private readonly SecurityFrameworkOptions _options;
    private readonly IServiceProvider _serviceProvider;

    public SecurityPerformanceTests()
    {
        var services = new ServiceCollection();
        services.AddSecurityFramework(options =>
        {
            options.EnableInMemoryStorage = true;
            options.Performance.MaxConcurrentRequests = 10000;
        });
        
        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task SecurityService_PerformanceUnderLoad()
    {
        // Arrange
        var securityService = _serviceProvider.GetRequiredService<ISecurityService>();
        var stopwatch = Stopwatch.StartNew();
        var tasks = new List<Task>();

        // Act - Simulate high load
        for (int i = 0; i < 1000; i++)
        {
            var ip = $"192.168.1.{i % 255}";
            tasks.Add(securityService.AssessIPAsync(ip));
        }

        await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        Assert.True(stopwatch.ElapsedMilliseconds < 5000, 
            $"Performance test took {stopwatch.ElapsedMilliseconds}ms, expected < 5000ms");
    }

    [Fact]
    public async Task PatternMatching_PerformanceTest()
    {
        // Arrange
        var patternService = _serviceProvider.GetRequiredService<IPatternService>();
        await patternService.LoadPatternsFromJsonAsync("test-patterns.json");
        
        var testInputs = GenerateTestInputs(1000);
        var stopwatch = Stopwatch.StartNew();

        // Act
        foreach (var input in testInputs)
        {
            await patternService.MatchPatternsAsync(input);
        }
        
        stopwatch.Stop();

        // Assert
        var avgTimePerMatch = stopwatch.ElapsedMilliseconds / (double)testInputs.Count;
        Assert.True(avgTimePerMatch < 10, 
            $"Average pattern matching time {avgTimePerMatch}ms, expected < 10ms");
    }
}
```

## Migration Strategies

### Gradual Migration Approach

```csharp
public class GradualMigrationService
{
    private readonly IFeatureManager _featureManager;
    private readonly ISecurityService _securityService;
    private readonly ILegacySecurityService _legacySecurityService;
    private readonly ILogger<GradualMigrationService> _logger;

    public GradualMigrationService(
        IFeatureManager featureManager,
        ISecurityService securityService,
        ILegacySecurityService legacySecurityService,
        ILogger<GradualMigrationService> logger)
    {
        _featureManager = featureManager;
        _securityService = securityService;
        _legacySecurityService = legacySecurityService;
        _logger = logger;
    }

    public async Task<ThreatAssessment> AssessThreatAsync(string ipAddress)
    {
        // Check feature flag for migration progress
        var useNewFramework = await _featureManager.IsEnabledAsync("UseSecurityFramework");
        var enableShadowMode = await _featureManager.IsEnabledAsync("SecurityFrameworkShadowMode");

        if (useNewFramework)
        {
            var newResult = await _securityService.AssessIPAsync(ipAddress);
            
            if (enableShadowMode)
            {
                // Run both systems and compare results
                _ = Task.Run(async () => await CompareLegacyResultAsync(ipAddress, newResult));
            }
            
            return newResult;
        }
        else
        {
            var legacyResult = await _legacySecurityService.AssessIPAsync(ipAddress);
            
            if (enableShadowMode)
            {
                // Run new system in shadow mode for comparison
                _ = Task.Run(async () => await CompareNewResultAsync(ipAddress, legacyResult));
            }
            
            return ConvertLegacyResult(legacyResult);
        }
    }

    private async Task CompareLegacyResultAsync(string ipAddress, ThreatAssessment newResult)
    {
        try
        {
            var legacyResult = await _legacySecurityService.AssessIPAsync(ipAddress);
            var convertedLegacy = ConvertLegacyResult(legacyResult);
            
            // Log differences for analysis
            if (Math.Abs(newResult.ThreatScore - convertedLegacy.ThreatScore) > 10)
            {
                _logger.LogInformation("Score difference detected for IP {IP}: New={NewScore}, Legacy={LegacyScore}",
                    ipAddress, newResult.ThreatScore, convertedLegacy.ThreatScore);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error comparing with legacy system for IP {IP}", ipAddress);
        }
    }
}
```

### Configuration Migration

```csharp
public class ConfigurationMigrationService
{
    public SecurityFrameworkOptions MigrateFromLegacyConfig(LegacySecurityConfig legacyConfig)
    {
        return new SecurityFrameworkOptions
        {
            EnableInMemoryStorage = true,
            DefaultThreatThreshold = legacyConfig.BlockingThreshold,
            DataRetentionDays = legacyConfig.LogRetentionDays,
            
            IPSecurity = new IPSecurityOptions
            {
                EnableBlocklist = legacyConfig.EnableIPBlocking,
                AutoBlockEnabled = legacyConfig.AutoBlock,
                AutoBlockThreshold = legacyConfig.AutoBlockScore,
                AutoBlockDuration = TimeSpan.FromHours(legacyConfig.BlockDurationHours),
                TrustedIPRanges = legacyConfig.WhitelistedIPs,
                BlockedCountries = legacyConfig.BlockedCountries
            },
            
            ParameterSecurity = new ParameterSecurityOptions
            {
                EnableParameterJackingDetection = true, // New feature
                DetectIDManipulation = true,
                DetectSequentialAccess = true,
                SequentialAccessThreshold = 5,
                AutoBlockOnHighRisk = legacyConfig.AutoBlock
            },
            
            Patterns = new PatternOptions
            {
                EnablePatternMatching = true,
                PatternDirectory = legacyConfig.RulesDirectory,
                AutoReload = legacyConfig.HotReload
            },
            
            Performance = new PerformanceOptions
            {
                EnableCaching = true,
                MaxConcurrentRequests = legacyConfig.MaxConcurrentRequests,
                EnableMetrics = legacyConfig.EnableMetrics
            }
        };
    }
}
```

## Troubleshooting

### Common Integration Issues

#### 1. Middleware Order Issues

```csharp
// ❌ Incorrect - SecurityFramework after authentication
app.UseAuthentication();
app.UseSecurityFramework(); // Wrong position

// ✅ Correct - SecurityFramework early in pipeline
app.UseSecurityFramework();
app.UseAuthentication();
app.UseAuthorization();
```

#### 2. Configuration Validation Errors

```csharp
// Add detailed validation error logging
builder.Services.AddOptions<SecurityFrameworkOptions>()
    .Bind(builder.Configuration.GetSection("SecurityFramework"))
    .ValidateDataAnnotations()
    .ValidateOnStart()
    .PostConfigure(options =>
    {
        var logger = serviceProvider.GetRequiredService<ILogger<SecurityFrameworkOptions>>();
        logger.LogInformation("SecurityFramework configuration loaded: {@Options}", options);
    });
```

#### 3. Database Connection Issues

```csharp
// Add connection string validation
public class SecurityDbContextHealthCheck : IHealthCheck
{
    private readonly SecurityDbContext _context;

    public SecurityDbContextHealthCheck(SecurityDbContext context)
    {
        _context = context;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, 
        CancellationToken cancellationToken = default)
    {
        try
        {
            await _context.Database.CanConnectAsync(cancellationToken);
            return HealthCheckResult.Healthy("Database connection successful");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database connection failed", ex);
        }
    }
}
```

### Diagnostic Tools

```csharp
public class SecurityDiagnosticsController : ControllerBase
{
    private readonly ISecurityService _securityService;
    private readonly IPatternService _patternService;
    private readonly IConfiguration _configuration;

    [HttpGet("diagnostics/security")]
    public async Task<ActionResult> GetSecurityDiagnostics()
    {
        var diagnostics = new
        {
            FrameworkVersion = typeof(SecurityFrameworkOptions).Assembly.GetName().Version?.ToString(),
            Configuration = new
            {
                InMemoryEnabled = _configuration.GetValue<bool>("SecurityFramework:EnableInMemoryStorage"),
                SQLiteEnabled = _configuration.GetValue<bool>("SecurityFramework:EnableSQLitePersistence"),
                ThreatThreshold = _configuration.GetValue<double>("SecurityFramework:DefaultThreatThreshold")
            },
            PatternStatus = new
            {
                PatternsLoaded = (await _patternService.GetActivePatternsAsync()).Count(),
                LastReload = DateTime.UtcNow // TODO: Get actual last reload time
            },
            PerformanceMetrics = new
            {
                // Add performance metrics
            }
        };

        return Ok(diagnostics);
    }
}
```

---

> **Next Steps**: After integration, refer to the [Pattern Development Guide](Pattern-Development.md) for creating custom threat patterns, and [Testing Guide](Testing-Guide.md) for comprehensive testing strategies.