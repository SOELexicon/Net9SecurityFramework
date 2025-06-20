using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SecurityFramework.Core.Models;
using System.Text.Json;

namespace SecurityFramework.Data;

/// <summary>
/// Entity Framework DbContext for the Security Framework
/// </summary>
public class SecurityDbContext : DbContext
{
    /// <summary>
    /// IP address records
    /// </summary>
    public DbSet<IPRecord> IPRecords { get; set; } = null!;

    /// <summary>
    /// Security incidents
    /// </summary>
    public DbSet<SecurityIncident> SecurityIncidents { get; set; } = null!;

    /// <summary>
    /// Parameter security incidents
    /// </summary>
    public DbSet<ParameterSecurityIncident> ParameterSecurityIncidents { get; set; } = null!;

    /// <summary>
    /// Threat detection patterns
    /// </summary>
    public DbSet<ThreatPattern> ThreatPatterns { get; set; } = null!;

    /// <summary>
    /// Initializes a new instance of the SecurityDbContext
    /// </summary>
    public SecurityDbContext(DbContextOptions<SecurityDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Configures the database context
    /// </summary>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);

        // Enable sensitive data logging in development
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
        {
            optionsBuilder.EnableSensitiveDataLogging();
        }

        // Enable detailed errors
        optionsBuilder.EnableDetailedErrors();

        // Configure query tracking behavior
        optionsBuilder.UseQueryTrackingBehavior(QueryTrackingBehavior.TrackAll);
    }

    /// <summary>
    /// Configures the entity model
    /// </summary>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure IPRecord entity
        ConfigureIPRecord(modelBuilder);

        // Configure SecurityIncident entity
        ConfigureSecurityIncident(modelBuilder);

        // Configure ParameterSecurityIncident entity
        ConfigureParameterSecurityIncident(modelBuilder);

        // Configure ThreatPattern entity
        ConfigureThreatPattern(modelBuilder);

        // Configure JSON serialization for complex properties
        ConfigureJsonSerialization(modelBuilder);

        // Configure indexes for performance
        ConfigureIndexes(modelBuilder);

        // Configure table names with schema
        ConfigureTableNames(modelBuilder);
    }

    /// <summary>
    /// Configures IPRecord entity
    /// </summary>
    private static void ConfigureIPRecord(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<IPRecord>();

        // Primary key
        entity.HasKey(e => e.Id);

        // Required properties
        entity.Property(e => e.IPAddress)
            .IsRequired()
            .HasMaxLength(45);

        entity.Property(e => e.TrustScore)
            .IsRequired()
            .HasPrecision(5, 2);

        entity.Property(e => e.ThreatScore)
            .IsRequired()
            .HasPrecision(5, 2);

        // Timestamps
        entity.Property(e => e.FirstSeen)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.LastSeen)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.CreatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.UpdatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        // Complex properties as JSON
        entity.OwnsOne(e => e.GeographicInfo, geo =>
        {
            geo.Property(g => g.CountryCode).HasMaxLength(2);
            geo.Property(g => g.CountryName).HasMaxLength(100);
            geo.Property(g => g.Region).HasMaxLength(100);
            geo.Property(g => g.City).HasMaxLength(100);
            geo.Property(g => g.TimeZone).HasMaxLength(50);
            geo.Property(g => g.ISP).HasMaxLength(200);
            geo.Property(g => g.Organization).HasMaxLength(200);
        });

        entity.OwnsOne(e => e.BehaviorProfile, behavior =>
        {
            behavior.Property(b => b.RequestFrequency).HasPrecision(10, 2);
            behavior.Property(b => b.AverageSessionDuration).HasPrecision(10, 2);
            behavior.Property(b => b.GeographicConsistency).HasPrecision(3, 2);
            behavior.Property(b => b.TimePatternConsistency).HasPrecision(3, 2);
            behavior.Property(b => b.ErrorRate).HasPrecision(5, 2);
            behavior.Property(b => b.AnomalyScore).HasPrecision(5, 2);
            behavior.Property(b => b.PrimaryUserAgent).HasMaxLength(500);
        });

        // Unique constraint on IP address
        entity.HasIndex(e => e.IPAddress)
            .IsUnique()
            .HasDatabaseName("IX_IPRecords_IPAddress_Unique");

        // Row version for concurrency
        entity.Property(e => e.Version)
            .IsRowVersion()
            .IsConcurrencyToken();
    }

    /// <summary>
    /// Configures SecurityIncident entity
    /// </summary>
    private static void ConfigureSecurityIncident(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<SecurityIncident>();

        // Primary key
        entity.HasKey(e => e.IncidentId);

        // Required properties
        entity.Property(e => e.Type)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Severity)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Status)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Title)
            .IsRequired()
            .HasMaxLength(200);

        entity.Property(e => e.Description)
            .HasMaxLength(2000);

        // IP addresses
        entity.Property(e => e.SourceIPAddress)
            .HasMaxLength(45);

        entity.Property(e => e.TargetIPAddress)
            .HasMaxLength(45);

        // User information
        entity.Property(e => e.UserId)
            .HasMaxLength(100);

        entity.Property(e => e.SessionId)
            .HasMaxLength(100);

        // Request information
        entity.Property(e => e.HttpMethod)
            .HasMaxLength(10);

        entity.Property(e => e.RequestPath)
            .HasMaxLength(2000);

        entity.Property(e => e.UserAgent)
            .HasMaxLength(1000);

        entity.Property(e => e.Referer)
            .HasMaxLength(2000);

        // Scores and metrics
        entity.Property(e => e.ThreatScore)
            .HasPrecision(5, 2);

        entity.Property(e => e.Confidence)
            .HasPrecision(5, 2);

        entity.Property(e => e.FalsePositiveLikelihood)
            .HasPrecision(5, 2);

        // Response information
        entity.Property(e => e.Response)
            .HasConversion<int>();

        // Timestamps
        entity.Property(e => e.DetectedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.CreatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.UpdatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        // Row version for concurrency
        entity.Property(e => e.Version)
            .IsRowVersion()
            .IsConcurrencyToken();

        // Configure owned types for complex properties
        entity.OwnsMany(e => e.Evidence, evidence =>
        {
            evidence.Property(ev => ev.Type).HasMaxLength(100);
            evidence.Property(ev => ev.Description).HasMaxLength(500);
            evidence.Property(ev => ev.Hash).HasMaxLength(128);
            evidence.Property(ev => ev.CollectedBy).HasMaxLength(200);
        });

        entity.OwnsMany(e => e.Timeline, timeline =>
        {
            timeline.Property(t => t.Action).HasMaxLength(200);
            timeline.Property(t => t.Details).HasMaxLength(1000);
            timeline.Property(t => t.Actor).HasMaxLength(200);
        });
    }

    /// <summary>
    /// Configures ParameterSecurityIncident entity
    /// </summary>
    private static void ConfigureParameterSecurityIncident(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<ParameterSecurityIncident>();

        // Primary key
        entity.HasKey(e => e.IncidentId);

        // Required properties
        entity.Property(e => e.Type)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Severity)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Status)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.IPAddress)
            .IsRequired()
            .HasMaxLength(45);

        entity.Property(e => e.HttpMethod)
            .IsRequired()
            .HasMaxLength(10);

        entity.Property(e => e.RequestPath)
            .IsRequired()
            .HasMaxLength(2000);

        entity.Property(e => e.ParameterName)
            .IsRequired()
            .HasMaxLength(200);

        entity.Property(e => e.AttemptedValue)
            .IsRequired()
            .HasMaxLength(1000);

        // Optional properties
        entity.Property(e => e.UserId)
            .HasMaxLength(100);

        entity.Property(e => e.SessionId)
            .HasMaxLength(100);

        entity.Property(e => e.OriginalValue)
            .HasMaxLength(1000);

        entity.Property(e => e.ExpectedValue)
            .HasMaxLength(1000);

        entity.Property(e => e.ResourceType)
            .HasMaxLength(100);

        entity.Property(e => e.ResourceId)
            .HasMaxLength(100);

        entity.Property(e => e.ResourceOwner)
            .HasMaxLength(100);

        entity.Property(e => e.Description)
            .HasMaxLength(1000);

        entity.Property(e => e.UserAgent)
            .HasMaxLength(1000);

        entity.Property(e => e.Referer)
            .HasMaxLength(2000);

        // Scores and metrics
        entity.Property(e => e.Confidence)
            .HasPrecision(5, 2);

        entity.Property(e => e.FalsePositiveLikelihood)
            .HasPrecision(5, 2);

        entity.Property(e => e.RiskScore)
            .HasPrecision(5, 2);

        // Detection information
        entity.Property(e => e.DetectionMethod)
            .HasMaxLength(100);

        entity.Property(e => e.BlockReason)
            .HasMaxLength(500);

        // Timestamps
        entity.Property(e => e.DetectedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.CreatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.UpdatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        // Row version for concurrency
        entity.Property(e => e.Version)
            .IsRowVersion()
            .IsConcurrencyToken();

        // Configure owned types
        entity.OwnsMany(e => e.Evidence, evidence =>
        {
            evidence.Property(ev => ev.Type).HasMaxLength(100);
            evidence.Property(ev => ev.Name).HasMaxLength(200);
            evidence.Property(ev => ev.Hash).HasMaxLength(128);
            evidence.Property(ev => ev.ContentType).HasMaxLength(100);
            evidence.Property(ev => ev.Source).HasMaxLength(200);
        });

        entity.OwnsOne(e => e.Impact, impact =>
        {
            impact.Property(i => i.Level).HasConversion<int>();
            impact.Property(i => i.BusinessImpact).HasMaxLength(1000);
            impact.Property(i => i.ComplianceImpact).HasMaxLength(1000);
        });
    }

    /// <summary>
    /// Configures ThreatPattern entity
    /// </summary>
    private static void ConfigureThreatPattern(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<ThreatPattern>();

        // Primary key
        entity.HasKey(e => e.PatternId);

        // Required properties
        entity.Property(e => e.Name)
            .IsRequired()
            .HasMaxLength(200);

        entity.Property(e => e.Category)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Severity)
            .IsRequired()
            .HasConversion<int>();

        entity.Property(e => e.Description)
            .HasMaxLength(1000);

        entity.Property(e => e.Subcategory)
            .HasMaxLength(100);

        entity.Property(e => e.Author)
            .HasMaxLength(200);

        entity.Property(e => e.Version)
            .HasMaxLength(20);

        // Scores and metrics
        entity.Property(e => e.BaseThreatScore)
            .HasPrecision(5, 2);

        entity.Property(e => e.Confidence)
            .HasPrecision(5, 2);

        // Timestamps
        entity.Property(e => e.LastUpdated)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        entity.Property(e => e.CreatedAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        // Row version for concurrency
        entity.Property(e => e.RowVersion)
            .IsRowVersion()
            .IsConcurrencyToken();

        // Configure owned types for rules
        entity.OwnsMany(e => e.Rules, rule =>
        {
            rule.Property(r => r.Name).HasMaxLength(200);
            rule.Property(r => r.Type).HasConversion<int>();
            rule.Property(r => r.Target).HasMaxLength(100);
            rule.Property(r => r.Operator).HasConversion<int>();
            rule.Property(r => r.Weight).HasPrecision(3, 2);
        });

        // Configure owned types for conditions
        entity.OwnsMany(e => e.Conditions, condition =>
        {
            condition.Property(c => c.Type).HasConversion<int>();
            condition.Property(c => c.Field).HasMaxLength(100);
            condition.Property(c => c.Operator).HasConversion<int>();
        });

        // Configure owned types for actions
        entity.OwnsMany(e => e.Actions, action =>
        {
            action.Property(a => a.Type).HasConversion<int>();
        });

        // Configure owned types for metrics
        entity.OwnsOne(e => e.Metrics, metrics =>
        {
            metrics.Property(m => m.AverageExecutionTime).HasPrecision(10, 2);
            metrics.Property(m => m.MaxExecutionTime).HasPrecision(10, 2);
        });

        // Unique constraint on pattern name
        entity.HasIndex(e => e.Name)
            .IsUnique()
            .HasDatabaseName("IX_ThreatPatterns_Name_Unique");
    }

    /// <summary>
    /// Configures JSON serialization for complex properties
    /// </summary>
    private static void ConfigureJsonSerialization(ModelBuilder modelBuilder)
    {
        var jsonSerializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };

        // Configure list properties as JSON
        modelBuilder.Entity<IPRecord>()
            .Property(e => e.Categories)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<IPCategory>>(v, jsonSerializerOptions) ?? new List<IPCategory>());

        modelBuilder.Entity<IPRecord>()
            .Property(e => e.Flags)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<IPRecord>()
            .Property(e => e.Metadata)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, jsonSerializerOptions) ?? new Dictionary<string, object>());

        // Configure SecurityIncident list properties
        modelBuilder.Entity<SecurityIncident>()
            .Property(e => e.MatchedPatterns)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<SecurityIncident>()
            .Property(e => e.RelatedIncidentIds)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<SecurityIncident>()
            .Property(e => e.Tags)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<SecurityIncident>()
            .Property(e => e.Metadata)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, jsonSerializerOptions) ?? new Dictionary<string, object>());

        // Configure ThreatPattern list properties
        modelBuilder.Entity<ThreatPattern>()
            .Property(e => e.Tags)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<ThreatPattern>()
            .Property(e => e.MitreAttackTechniques)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<ThreatPattern>()
            .Property(e => e.CVEReferences)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<ThreatPattern>()
            .Property(e => e.References)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<List<string>>(v, jsonSerializerOptions) ?? new List<string>());

        modelBuilder.Entity<ThreatPattern>()
            .Property(e => e.Metadata)
            .HasConversion(
                v => JsonSerializer.Serialize(v, jsonSerializerOptions),
                v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, jsonSerializerOptions) ?? new Dictionary<string, object>());
    }

    /// <summary>
    /// Configures database indexes for performance
    /// </summary>
    private static void ConfigureIndexes(ModelBuilder modelBuilder)
    {
        // IPRecord indexes
        modelBuilder.Entity<IPRecord>()
            .HasIndex(e => e.IPAddress)
            .HasDatabaseName("IX_IPRecords_IPAddress");

        modelBuilder.Entity<IPRecord>()
            .HasIndex(e => e.LastSeen)
            .HasDatabaseName("IX_IPRecords_LastSeen");

        modelBuilder.Entity<IPRecord>()
            .HasIndex(e => e.ThreatScore)
            .HasDatabaseName("IX_IPRecords_ThreatScore");

        modelBuilder.Entity<IPRecord>()
            .HasIndex(e => e.IsBlocked)
            .HasDatabaseName("IX_IPRecords_IsBlocked");

        // SecurityIncident indexes
        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => e.DetectedAt)
            .HasDatabaseName("IX_SecurityIncidents_DetectedAt");

        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => e.SourceIPAddress)
            .HasDatabaseName("IX_SecurityIncidents_SourceIPAddress");

        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => e.UserId)
            .HasDatabaseName("IX_SecurityIncidents_UserId");

        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => e.Type)
            .HasDatabaseName("IX_SecurityIncidents_Type");

        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => e.Severity)
            .HasDatabaseName("IX_SecurityIncidents_Severity");

        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => e.Status)
            .HasDatabaseName("IX_SecurityIncidents_Status");

        // ParameterSecurityIncident indexes
        modelBuilder.Entity<ParameterSecurityIncident>()
            .HasIndex(e => e.DetectedAt)
            .HasDatabaseName("IX_ParameterSecurityIncidents_DetectedAt");

        modelBuilder.Entity<ParameterSecurityIncident>()
            .HasIndex(e => e.IPAddress)
            .HasDatabaseName("IX_ParameterSecurityIncidents_IPAddress");

        modelBuilder.Entity<ParameterSecurityIncident>()
            .HasIndex(e => e.UserId)
            .HasDatabaseName("IX_ParameterSecurityIncidents_UserId");

        modelBuilder.Entity<ParameterSecurityIncident>()
            .HasIndex(e => e.Type)
            .HasDatabaseName("IX_ParameterSecurityIncidents_Type");

        modelBuilder.Entity<ParameterSecurityIncident>()
            .HasIndex(e => e.ParameterName)
            .HasDatabaseName("IX_ParameterSecurityIncidents_ParameterName");

        // ThreatPattern indexes
        modelBuilder.Entity<ThreatPattern>()
            .HasIndex(e => e.Category)
            .HasDatabaseName("IX_ThreatPatterns_Category");

        modelBuilder.Entity<ThreatPattern>()
            .HasIndex(e => e.Severity)
            .HasDatabaseName("IX_ThreatPatterns_Severity");

        modelBuilder.Entity<ThreatPattern>()
            .HasIndex(e => e.IsEnabled)
            .HasDatabaseName("IX_ThreatPatterns_IsEnabled");

        modelBuilder.Entity<ThreatPattern>()
            .HasIndex(e => e.LastUpdated)
            .HasDatabaseName("IX_ThreatPatterns_LastUpdated");

        // Composite indexes for common queries
        modelBuilder.Entity<SecurityIncident>()
            .HasIndex(e => new { e.DetectedAt, e.Severity })
            .HasDatabaseName("IX_SecurityIncidents_DetectedAt_Severity");

        modelBuilder.Entity<IPRecord>()
            .HasIndex(e => new { e.ThreatScore, e.LastSeen })
            .HasDatabaseName("IX_IPRecords_ThreatScore_LastSeen");
    }

    /// <summary>
    /// Configures table names with schema
    /// </summary>
    private static void ConfigureTableNames(ModelBuilder modelBuilder)
    {
        // Use security schema for better organization
        modelBuilder.Entity<IPRecord>()
            .ToTable("IPRecords", "security");

        modelBuilder.Entity<SecurityIncident>()
            .ToTable("SecurityIncidents", "security");

        modelBuilder.Entity<ParameterSecurityIncident>()
            .ToTable("ParameterSecurityIncidents", "security");

        modelBuilder.Entity<ThreatPattern>()
            .ToTable("ThreatPatterns", "security");
    }

    /// <summary>
    /// Override SaveChanges to automatically update timestamps
    /// </summary>
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return await base.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Override SaveChanges to automatically update timestamps
    /// </summary>
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }

    /// <summary>
    /// Updates timestamps for entities being modified
    /// </summary>
    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e.State == EntityState.Added || e.State == EntityState.Modified);

        foreach (var entry in entries)
        {
            if (entry.Entity is IPRecord ipRecord)
            {
                if (entry.State == EntityState.Modified)
                {
                    ipRecord.UpdatedAt = DateTime.UtcNow;
                }
            }
            else if (entry.Entity is SecurityIncident incident)
            {
                if (entry.State == EntityState.Modified)
                {
                    incident.UpdatedAt = DateTime.UtcNow;
                }
            }
            else if (entry.Entity is ParameterSecurityIncident paramIncident)
            {
                if (entry.State == EntityState.Modified)
                {
                    paramIncident.UpdatedAt = DateTime.UtcNow;
                }
            }
        }
    }
}