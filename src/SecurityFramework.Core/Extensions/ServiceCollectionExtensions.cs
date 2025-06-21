using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecurityFramework.Core.Abstractions;
using SecurityFramework.Core.Services;
using SecurityFramework.Data;
using SecurityFramework.Middleware;
using SecurityFramework.Services;

namespace SecurityFramework.Core.Extensions;

/// <summary>
/// Extension methods for configuring Security Framework services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the complete Security Framework with default configuration
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Configuration instance</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddSecurityFramework(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return services.AddSecurityFramework(configuration, options => { });
    }

    /// <summary>
    /// Adds the complete Security Framework with custom configuration
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Configuration instance</param>
    /// <param name="configureOptions">Action to configure framework options</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddSecurityFramework(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<SecurityFrameworkOptions> configureOptions)
    {
        var options = new SecurityFrameworkOptions();
        configureOptions(options);

        // Configure framework options
        services.Configure<SecurityFrameworkOptions>(opts =>
        {
            opts.EnableIPTracking = options.EnableIPTracking;
            opts.EnableParameterSecurity = options.EnableParameterSecurity;
            opts.EnablePatternMatching = options.EnablePatternMatching;
            opts.EnableRealTimeMonitoring = options.EnableRealTimeMonitoring;
            opts.EnablePersistence = options.EnablePersistence;
            opts.EnableMiddleware = options.EnableMiddleware;
            opts.ThreatScoringOptions = options.ThreatScoringOptions;
            opts.PatternOptions = options.PatternOptions;
            opts.MiddlewareOptions = options.MiddlewareOptions;
        });

        // Add core services
        services.AddSecurityFrameworkCore(options);

        // Add data layer if persistence is enabled
        if (options.EnablePersistence)
        {
            services.AddSecurityFrameworkData(configuration);
        }
        else
        {
            services.AddSecurityFrameworkInMemoryData();
        }

        return services;
    }

    /// <summary>
    /// Adds core Security Framework services without data layer
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="options">Framework options</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddSecurityFrameworkCore(
        this IServiceCollection services,
        SecurityFrameworkOptions? options = null)
    {
        options ??= new SecurityFrameworkOptions();

        // Register core abstractions and services
        services.AddScoped<IThreatScoringEngine, ThreatScoringEngine>();
        services.AddScoped<IRiskAssessmentEngine, RiskAssessmentEngine>();

        if (options.EnableIPTracking)
        {
            services.AddScoped<ISecurityService, SecurityService>();
        }

        if (options.EnablePatternMatching)
        {
            services.AddScoped<IPatternService, PatternService>();
        }

        if (options.EnableParameterSecurity)
        {
            services.AddScoped<IParameterSecurityService, ParameterSecurityService>();
        }

        // Configure options
        if (options.ThreatScoringOptions != null)
        {
            services.Configure<ThreatScoringOptions>(opts =>
            {
                opts.BaseScoreWeight = options.ThreatScoringOptions.BaseScoreWeight;
                opts.BehavioralScoreWeight = options.ThreatScoringOptions.BehavioralScoreWeight;
                opts.GeographicScoreWeight = options.ThreatScoringOptions.GeographicScoreWeight;
                opts.TemporalScoreWeight = options.ThreatScoringOptions.TemporalScoreWeight;
                opts.PatternScoreWeight = options.ThreatScoringOptions.PatternScoreWeight;
                opts.FrequencyScoreWeight = options.ThreatScoringOptions.FrequencyScoreWeight;
                opts.ReputationScoreWeight = options.ThreatScoringOptions.ReputationScoreWeight;
                opts.MinThreatScore = options.ThreatScoringOptions.MinThreatScore;
                opts.MaxThreatScore = options.ThreatScoringOptions.MaxThreatScore;
            });
        }

        if (options.PatternOptions != null)
        {
            services.Configure<PatternServiceOptions>(opts =>
            {
                opts.PatternDirectory = options.PatternOptions.PatternDirectory;
                opts.EnableHotReload = options.PatternOptions.EnableHotReload;
                opts.CachePatterns = options.PatternOptions.CachePatterns;
                opts.PatternCacheDuration = options.PatternOptions.PatternCacheDuration;
            });
        }

        return services;
    }

    /// <summary>
    /// Adds Security Framework for high-performance scenarios
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Configuration instance</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddSecurityFrameworkHighPerformance(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return services.AddSecurityFramework(configuration, options =>
        {
            options.EnableIPTracking = true;
            options.EnableParameterSecurity = true;
            options.EnablePatternMatching = true;
            options.EnablePersistence = true;
            options.EnableMiddleware = true;

            // Optimize for performance
            options.ThreatScoringOptions = new ThreatScoringOptions
            {
                BaseScoreWeight = 1.0,
                BehavioralScoreWeight = 0.8,
                GeographicScoreWeight = 0.6,
                TemporalScoreWeight = 0.7,
                PatternScoreWeight = 1.2,
                FrequencyScoreWeight = 0.9,
                ReputationScoreWeight = 1.1
            };

            options.PatternOptions = new PatternServiceOptions
            {
                PatternDirectory = "patterns",
                EnableHotReload = false, // Disable for performance
                CachePatterns = true,
                PatternCacheDuration = TimeSpan.FromHours(1)
            };
        });
    }

    /// <summary>
    /// Adds Security Framework for development scenarios
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Configuration instance</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddSecurityFrameworkDevelopment(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return services.AddSecurityFramework(configuration, options =>
        {
            options.EnableIPTracking = true;
            options.EnableParameterSecurity = true;
            options.EnablePatternMatching = true;
            options.EnablePersistence = false; // Use in-memory for development
            options.EnableMiddleware = true;

            options.PatternOptions = new PatternServiceOptions
            {
                PatternDirectory = "patterns",
                EnableHotReload = true, // Enable for development
                CachePatterns = false,
                PatternCacheDuration = TimeSpan.FromMinutes(5)
            };
        });
    }

    /// <summary>
    /// Adds Security Framework with minimal features for testing
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddSecurityFrameworkMinimal(
        this IServiceCollection services)
    {
        return services.AddSecurityFrameworkCore(new SecurityFrameworkOptions
        {
            EnableIPTracking = true,
            EnableParameterSecurity = false,
            EnablePatternMatching = false,
            EnablePersistence = false,
            EnableMiddleware = false,
            EnableRealTimeMonitoring = false
        });
    }
}

/// <summary>
/// Configuration options for the Security Framework
/// </summary>
public class SecurityFrameworkOptions
{
    /// <summary>
    /// Enable IP tracking and threat assessment
    /// </summary>
    public bool EnableIPTracking { get; set; } = true;

    /// <summary>
    /// Enable parameter security and IDOR protection
    /// </summary>
    public bool EnableParameterSecurity { get; set; } = true;

    /// <summary>
    /// Enable pattern-based threat detection
    /// </summary>
    public bool EnablePatternMatching { get; set; } = true;

    /// <summary>
    /// Enable real-time monitoring features (SignalR/WebSocket)
    /// </summary>
    public bool EnableRealTimeMonitoring { get; set; } = false;

    /// <summary>
    /// Enable SQLite persistence (otherwise use in-memory only)
    /// </summary>
    public bool EnablePersistence { get; set; } = true;

    /// <summary>
    /// Enable automatic middleware registration
    /// </summary>
    public bool EnableMiddleware { get; set; } = true;

    /// <summary>
    /// Threat scoring engine options
    /// </summary>
    public ThreatScoringOptions? ThreatScoringOptions { get; set; }

    /// <summary>
    /// Pattern service options
    /// </summary>
    public PatternServiceOptions? PatternOptions { get; set; }

    /// <summary>
    /// Middleware configuration options
    /// </summary>
    public MiddlewareOptions? MiddlewareOptions { get; set; }
}

/// <summary>
/// Options for threat scoring engine configuration
/// </summary>
public class ThreatScoringOptions
{
    public double BaseScoreWeight { get; set; } = 1.0;
    public double BehavioralScoreWeight { get; set; } = 0.8;
    public double GeographicScoreWeight { get; set; } = 0.6;
    public double TemporalScoreWeight { get; set; } = 0.7;
    public double PatternScoreWeight { get; set; } = 1.2;
    public double FrequencyScoreWeight { get; set; } = 0.9;
    public double ReputationScoreWeight { get; set; } = 1.0;
    public double MinThreatScore { get; set; } = 0.0;
    public double MaxThreatScore { get; set; } = 100.0;
}

/// <summary>
/// Options for pattern service configuration
/// </summary>
public class PatternServiceOptions
{
    public string PatternDirectory { get; set; } = "patterns";
    public bool EnableHotReload { get; set; } = true;
    public bool CachePatterns { get; set; } = true;
    public TimeSpan PatternCacheDuration { get; set; } = TimeSpan.FromMinutes(30);
}

/// <summary>
/// Options for middleware configuration
/// </summary>
public class MiddlewareOptions
{
    public bool EnableIPSecurityMiddleware { get; set; } = true;
    public bool EnableParameterSecurityMiddleware { get; set; } = true;
    public bool EnableRequestLoggingMiddleware { get; set; } = true;
    public int RequestTimeoutSeconds { get; set; } = 30;
    public bool LogBlockedRequests { get; set; } = true;
    public bool ReturnDetailedErrors { get; set; } = false;
}