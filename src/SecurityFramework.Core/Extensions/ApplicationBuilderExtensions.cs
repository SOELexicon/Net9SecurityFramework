using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecurityFramework.Middleware;

namespace SecurityFramework.Core.Extensions;

/// <summary>
/// Extension methods for configuring Security Framework middleware
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds Security Framework middleware with default configuration
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFramework(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetService<IOptions<SecurityFrameworkOptions>>()?.Value 
                     ?? new SecurityFrameworkOptions();

        return app.UseSecurityFramework(options);
    }

    /// <summary>
    /// Adds Security Framework middleware with custom configuration
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="options">Framework options</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFramework(
        this IApplicationBuilder app, 
        SecurityFrameworkOptions options)
    {
        if (!options.EnableMiddleware)
            return app;

        var middlewareOptions = options.MiddlewareOptions ?? new MiddlewareOptions();

        // Add middleware in the correct order for security processing
        if (middlewareOptions.EnableRequestLoggingMiddleware)
        {
            app.UseSecurityRequestLogging();
        }

        if (middlewareOptions.EnableIPSecurityMiddleware && options.EnableIPTracking)
        {
            app.UseIPSecurity();
        }

        if (middlewareOptions.EnableParameterSecurityMiddleware && options.EnableParameterSecurity)
        {
            app.UseParameterSecurity();
        }

        return app;
    }

    /// <summary>
    /// Adds Security Framework middleware for high-performance scenarios
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFrameworkHighPerformance(this IApplicationBuilder app)
    {
        return app.UseSecurityFramework(new SecurityFrameworkOptions
        {
            EnableMiddleware = true,
            MiddlewareOptions = new MiddlewareOptions
            {
                EnableIPSecurityMiddleware = true,
                EnableParameterSecurityMiddleware = true,
                EnableRequestLoggingMiddleware = false, // Disable logging for performance
                RequestTimeoutSeconds = 10,
                LogBlockedRequests = false,
                ReturnDetailedErrors = false
            }
        });
    }

    /// <summary>
    /// Adds Security Framework middleware for development scenarios
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFrameworkDevelopment(this IApplicationBuilder app)
    {
        return app.UseSecurityFramework(new SecurityFrameworkOptions
        {
            EnableMiddleware = true,
            MiddlewareOptions = new MiddlewareOptions
            {
                EnableIPSecurityMiddleware = true,
                EnableParameterSecurityMiddleware = true,
                EnableRequestLoggingMiddleware = true,
                RequestTimeoutSeconds = 60,
                LogBlockedRequests = true,
                ReturnDetailedErrors = true // Enable detailed errors for development
            }
        });
    }

    /// <summary>
    /// Adds IP security middleware
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseIPSecurity(this IApplicationBuilder app)
    {
        return app.UseMiddleware<IPSecurityMiddleware>();
    }

    /// <summary>
    /// Adds parameter security middleware
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseParameterSecurity(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ParameterSecurityMiddleware>();
    }

    /// <summary>
    /// Adds security request logging middleware
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityRequestLogging(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityRequestLoggingMiddleware>();
    }

    /// <summary>
    /// Adds custom middleware for specific security scenarios
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="configure">Action to configure middleware options</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseSecurityFrameworkCustom(
        this IApplicationBuilder app,
        Action<MiddlewareOptions> configure)
    {
        var options = new MiddlewareOptions();
        configure(options);

        return app.UseSecurityFramework(new SecurityFrameworkOptions
        {
            EnableMiddleware = true,
            MiddlewareOptions = options
        });
    }

    /// <summary>
    /// Ensures the Security Framework database is initialized
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder EnsureSecurityFrameworkDatabase(this IApplicationBuilder app)
    {
        // This will be called during application startup
        Task.Run(async () =>
        {
            await app.ApplicationServices.EnsureSecurityFrameworkDatabaseAsync();
        });

        return app;
    }
}