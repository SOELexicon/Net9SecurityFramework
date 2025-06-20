# Migration Guide

This document provides comprehensive guidance for upgrading between versions of the Security Framework, including breaking changes, migration steps, and compatibility information.

## Table of Contents

1. [Overview](#overview)
2. [Migration Planning](#migration-planning)
3. [Version-Specific Migrations](#version-specific-migrations)
4. [Breaking Changes](#breaking-changes)
5. [Configuration Migrations](#configuration-migrations)
6. [Database Migrations](#database-migrations)
7. [Code Migrations](#code-migrations)
8. [Testing Migrations](#testing-migrations)
9. [Rollback Procedures](#rollback-procedures)
10. [Migration Tools](#migration-tools)

## Overview

The Security Framework follows semantic versioning and provides migration paths between all supported versions. This guide helps you plan and execute upgrades while minimizing downtime and ensuring data integrity.

### Migration Strategy

- **Patch Versions** (1.0.0 → 1.0.1): Automatic, no migration required
- **Minor Versions** (1.0.0 → 1.1.0): Configuration updates may be needed
- **Major Versions** (1.0.0 → 2.0.0): May require code changes and data migration

### Supported Upgrade Paths

- Direct upgrades within the same major version (1.x → 1.y)
- Sequential major version upgrades (1.x → 2.0 → 3.0)
- Skip-level upgrades are supported but require additional validation

## Migration Planning

### Pre-Migration Checklist

Before starting any migration:

1. **Backup Your Data**
   ```bash
   # SQLite backup
   sqlite3 /path/to/security.db ".backup /path/to/backup/security_backup.db"
   
   # Configuration backup
   cp -r /app/config /app/config_backup
   
   # Pattern files backup
   cp -r /app/patterns /app/patterns_backup
   ```

2. **Review Current Configuration**
   ```bash
   # Document current settings
   cat appsettings.json > migration_current_config.json
   
   # Check current version
   dotnet --version
   ```

3. **Test in Staging Environment**
   - Deploy to staging environment first
   - Run full test suite
   - Validate performance benchmarks
   - Verify security controls

4. **Plan Rollback Strategy**
   - Document rollback steps
   - Prepare rollback scripts
   - Test rollback procedure in staging

### Migration Timeline Planning

**Small deployments (< 1000 users):**
- Planning: 1-2 days
- Testing: 2-3 days
- Migration: 2-4 hours
- Validation: 1 day

**Large deployments (> 10,000 users):**
- Planning: 1-2 weeks
- Testing: 1-2 weeks
- Migration: 4-8 hours
- Validation: 2-3 days

## Version-Specific Migrations

### Migration from 1.0.x to 1.1.x (Minor Version)

**Changes in 1.1.x:**
- Added real-time monitoring features
- Enhanced pattern matching capabilities
- Improved performance optimizations

**Migration Steps:**

1. **Update Configuration**
   ```json
   {
     "SecurityFramework": {
       "RealTimeMonitoring": {
         "Enabled": false,
         "EnableSignalR": false,
         "EnableWebSockets": false
       }
     }
   }
   ```

2. **Database Schema Updates**
   ```bash
   dotnet ef database update --project SecurityFramework.Data
   ```

3. **Pattern File Updates**
   - New pattern templates available in `/patterns/v1.1/`
   - Copy new patterns or update existing ones
   - Validate pattern syntax with new features

**Breaking Changes:** None

**Deprecations:**
- `SecurityFrameworkOptions.LegacyMode` (will be removed in 2.0.0)

### Migration from 1.x to 2.0.x (Major Version)

**Major Changes in 2.0.x:**
- New configuration schema
- Enhanced security interfaces
- Multi-tenant support
- ML.NET integration

**Migration Steps:**

1. **Pre-Migration Assessment**
   ```bash
   # Run migration assessment tool
   dotnet run --project SecurityFramework.Tools.Migration -- assess --version 2.0.0
   ```

2. **Configuration Migration**
   ```bash
   # Use automated configuration migrator
   dotnet run --project SecurityFramework.Tools.Migration -- config --from 1.x --to 2.0
   ```

3. **Code Updates Required**
   ```csharp
   // OLD (1.x)
   services.AddSecurityFramework(options =>
   {
       options.DefaultThreatThreshold = 50;
       options.EnableInMemoryStorage = true;
   });
   
   // NEW (2.0)
   services.AddSecurityFramework(options =>
   {
       options.ThreatDetection.DefaultThreshold = 50;
       options.Storage.EnableInMemoryCache = true;
       options.Storage.EnableSQLitePersistence = true;
   });
   ```

4. **Interface Updates**
   ```csharp
   // OLD (1.x)
   public class CustomSecurityService : ISecurityService
   {
       public async Task<ThreatAssessment> AssessIP(string ipAddress)
       {
           // Implementation
       }
   }
   
   // NEW (2.0)
   public class CustomSecurityService : ISecurityService
   {
       public async Task<ThreatAssessment> AssessIPAsync(string ipAddress, CancellationToken cancellationToken = default)
       {
           // Implementation with async suffix and cancellation support
       }
   }
   ```

**Breaking Changes:**
- `ISecurityService.AssessIP` → `ISecurityService.AssessIPAsync`
- Configuration schema restructured
- Minimum .NET version raised to .NET 9

## Breaking Changes

### Version 2.0.0 Breaking Changes

#### API Changes

```csharp
// BREAKING: Method signature changes
// OLD
public interface ISecurityService
{
    Task<ThreatAssessment> AssessIP(string ipAddress);
    void Configure(SecurityOptions options);
}

// NEW
public interface ISecurityService
{
    Task<ThreatAssessment> AssessIPAsync(string ipAddress, CancellationToken cancellationToken = default);
    Task ConfigureAsync(SecurityFrameworkOptions options, CancellationToken cancellationToken = default);
}
```

#### Configuration Changes

```json
// OLD Configuration (1.x)
{
  "SecurityFramework": {
    "DefaultThreatThreshold": 50,
    "EnableInMemoryStorage": true,
    "EnableSQLitePersistence": false,
    "RealTimeEnabled": false
  }
}

// NEW Configuration (2.0)
{
  "SecurityFramework": {
    "ThreatDetection": {
      "DefaultThreshold": 50,
      "EnableMLEnhancement": false
    },
    "Storage": {
      "EnableInMemoryCache": true,
      "EnableSQLitePersistence": false
    },
    "RealTimeMonitoring": {
      "Enabled": false,
      "EnableSignalR": false
    }
  }
}
```

#### Dependency Changes

```xml
<!-- Remove old packages -->
<PackageReference Include="SecurityFramework" Version="1.x.x" />

<!-- Add new packages -->
<PackageReference Include="SecurityFramework.Core" Version="2.0.0" />
<PackageReference Include="SecurityFramework.Services" Version="2.0.0" />
<PackageReference Include="SecurityFramework.Middleware" Version="2.0.0" />

<!-- Optional packages -->
<PackageReference Include="SecurityFramework.RealTime" Version="2.0.0" Condition="$(EnableRealTime)" />
<PackageReference Include="SecurityFramework.ML" Version="2.0.0" Condition="$(EnableML)" />
```

### Version 3.0.0 Breaking Changes (Future)

**Planned Breaking Changes:**
- Remove deprecated APIs from 2.x
- Require .NET 10 minimum
- Enhanced multi-tenant architecture
- New compliance framework integration

## Configuration Migrations

### Automated Configuration Migration

The Security Framework includes tools to automatically migrate configuration files:

```bash
# Install migration tools
dotnet tool install --global SecurityFramework.Tools.Migration

# Migrate configuration
security-migrate config --from 1.5.0 --to 2.0.0 --input appsettings.json --output appsettings.migrated.json

# Validate migrated configuration
security-migrate validate --config appsettings.migrated.json --version 2.0.0
```

### Manual Configuration Migration

For complex scenarios, manual migration may be required:

```csharp
public class ConfigurationMigrator
{
    public static SecurityFrameworkOptions MigrateFrom1x(LegacySecurityOptions legacy)
    {
        return new SecurityFrameworkOptions
        {
            ThreatDetection = new ThreatDetectionOptions
            {
                DefaultThreshold = legacy.DefaultThreatThreshold,
                EnablePatternMatching = legacy.EnablePatternMatching,
                PatternDirectory = legacy.PatternDirectory
            },
            Storage = new StorageOptions
            {
                EnableInMemoryCache = legacy.EnableInMemoryStorage,
                EnableSQLitePersistence = legacy.EnableSQLitePersistence,
                SQLiteConnectionString = legacy.SQLiteConnectionString
            },
            RealTimeMonitoring = new RealTimeMonitoringOptions
            {
                Enabled = legacy.RealTimeEnabled,
                EnableSignalR = legacy.RealTimeEnabled,
                EnableWebSockets = legacy.RealTimeEnabled
            }
        };
    }
}
```

## Database Migrations

### Entity Framework Migrations

The framework uses Entity Framework migrations for database schema changes:

```bash
# Check current migration status
dotnet ef migrations list --project SecurityFramework.Data

# Apply pending migrations
dotnet ef database update --project SecurityFramework.Data

# Generate migration script for manual execution
dotnet ef migrations script --project SecurityFramework.Data --output migration.sql
```

### Custom Data Migrations

For complex data transformations:

```csharp
public class DataMigrationService
{
    public async Task MigrateTo2_0_0Async()
    {
        using var transaction = await _context.Database.BeginTransactionAsync();
        
        try
        {
            // Migrate IP records to new schema
            await MigrateIPRecordsAsync();
            
            // Migrate security incidents
            await MigrateSecurityIncidentsAsync();
            
            // Update pattern configurations
            await MigratePatternsAsync();
            
            await transaction.CommitAsync();
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }
    
    private async Task MigrateIPRecordsAsync()
    {
        var legacyRecords = await _context.LegacyIPRecords.ToListAsync();
        
        foreach (var legacy in legacyRecords)
        {
            var newRecord = new IPRecord
            {
                IPAddress = legacy.IPAddress,
                TrustScore = legacy.TrustScore,
                ThreatScore = legacy.ThreatScore,
                LastSeen = legacy.LastSeen,
                // Map new fields with default values
                BehaviorProfile = new IPBehaviorProfile
                {
                    RequestFrequency = legacy.RequestCount / 24.0, // Approximate
                    GeographicConsistency = 1.0 // Default high consistency
                }
            };
            
            _context.IPRecords.Add(newRecord);
        }
        
        await _context.SaveChangesAsync();
    }
}
```

### SQLite-Specific Migrations

For SQLite deployments with schema changes that require data preservation:

```sql
-- Example: Adding new columns to existing table
-- SQLite doesn't support ALTER TABLE for complex changes

-- 1. Create new table with updated schema
CREATE TABLE IPRecords_new (
    Id TEXT PRIMARY KEY,
    IPAddress TEXT NOT NULL,
    TrustScore REAL NOT NULL,
    ThreatScore REAL NOT NULL,
    LastSeen TEXT NOT NULL,
    -- New columns in 2.0
    BehaviorProfileJson TEXT,
    GeographicInfo TEXT,
    CreatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Copy data from old table
INSERT INTO IPRecords_new (Id, IPAddress, TrustScore, ThreatScore, LastSeen, CreatedAt)
SELECT Id, IPAddress, TrustScore, ThreatScore, LastSeen, LastSeen
FROM IPRecords;

-- 3. Drop old table and rename new table
DROP TABLE IPRecords;
ALTER TABLE IPRecords_new RENAME TO IPRecords;

-- 4. Recreate indexes
CREATE INDEX IX_IPRecords_IPAddress ON IPRecords(IPAddress);
CREATE INDEX IX_IPRecords_LastSeen ON IPRecords(LastSeen);
```

## Code Migrations

### Updating Service Registration

```csharp
// OLD (1.x) - Program.cs or Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddSecurityFramework(options =>
    {
        options.DefaultThreatThreshold = 50;
        options.EnableInMemoryStorage = true;
    });
}

// NEW (2.0) - Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSecurityFramework(options =>
{
    options.ThreatDetection.DefaultThreshold = 50;
    options.Storage.EnableInMemoryCache = true;
    options.Storage.EnableSQLitePersistence = true;
});

// Optional real-time features
if (builder.Configuration.GetValue<bool>("SecurityFramework:RealTimeMonitoring:Enabled"))
{
    builder.Services.AddSecurityFrameworkRealTime();
}

var app = builder.Build();
```

### Updating Middleware Registration

```csharp
// OLD (1.x)
public void Configure(IApplicationBuilder app)
{
    app.UseSecurityFramework();
}

// NEW (2.0)
var app = builder.Build();

app.UseSecurityFramework(options =>
{
    options.EnableIPValidation = true;
    options.EnableParameterSecurity = true;
    options.EnableRealTimeMonitoring = app.Configuration.GetValue<bool>("RealTime:Enabled");
});
```

### Updating Custom Services

```csharp
// OLD (1.x) - Custom threat scorer
public class CustomThreatScorer : IThreatScorer
{
    public double CalculateScore(IPRecord record)
    {
        return record.ThreatScore * 1.2;
    }
}

// NEW (2.0) - Enhanced interface with async support
public class CustomThreatScorer : IThreatScorer
{
    public async Task<double> CalculateScoreAsync(IPRecord record, ThreatContext context, CancellationToken cancellationToken = default)
    {
        // Enhanced scoring with context
        var baseScore = record.ThreatScore;
        var contextMultiplier = await CalculateContextMultiplierAsync(context, cancellationToken);
        
        return baseScore * contextMultiplier;
    }
    
    private async Task<double> CalculateContextMultiplierAsync(ThreatContext context, CancellationToken cancellationToken)
    {
        // New context-aware scoring logic
        return context.TimeOfDay switch
        {
            var time when time.Hour >= 9 && time.Hour <= 17 => 1.0, // Business hours
            _ => 1.3 // Outside business hours - higher risk
        };
    }
}
```

## Testing Migrations

### Migration Testing Strategy

1. **Unit Tests for Migration Logic**
   ```csharp
   [TestClass]
   public class ConfigurationMigrationTests
   {
       [TestMethod]
       public void MigrateFrom1x_ShouldPreserveAllSettings()
       {
           // Arrange
           var legacy = new LegacySecurityOptions
           {
               DefaultThreatThreshold = 75,
               EnableInMemoryStorage = true,
               PatternDirectory = "/custom/patterns"
           };
           
           // Act
           var migrated = ConfigurationMigrator.MigrateFrom1x(legacy);
           
           // Assert
           Assert.AreEqual(75, migrated.ThreatDetection.DefaultThreshold);
           Assert.IsTrue(migrated.Storage.EnableInMemoryCache);
           Assert.AreEqual("/custom/patterns", migrated.PatternMatching.PatternDirectory);
       }
   }
   ```

2. **Integration Tests**
   ```csharp
   [TestClass]
   public class MigrationIntegrationTests
   {
       [TestMethod]
       public async Task FullMigration_From1x_To2x_ShouldPreserveData()
       {
           // Arrange - Setup 1.x database
           await SetupLegacyDatabaseAsync();
           
           // Act - Perform migration
           var migrationService = new DataMigrationService(_context);
           await migrationService.MigrateTo2_0_0Async();
           
           // Assert - Validate migrated data
           var migratedRecords = await _context.IPRecords.ToListAsync();
           Assert.IsTrue(migratedRecords.Count > 0);
           Assert.IsTrue(migratedRecords.All(r => r.BehaviorProfile != null));
       }
   }
   ```

3. **Performance Testing**
   ```csharp
   [TestMethod]
   public async Task MigrationPerformance_LargeDataset_ShouldCompleteWithinTimeout()
   {
       // Arrange - Create large dataset
       await CreateLargeDatasetAsync(100000); // 100k records
       
       var stopwatch = Stopwatch.StartNew();
       
       // Act
       await _migrationService.MigrateTo2_0_0Async();
       
       stopwatch.Stop();
       
       // Assert - Should complete within reasonable time
       Assert.IsTrue(stopwatch.Elapsed < TimeSpan.FromMinutes(30));
   }
   ```

## Rollback Procedures

### Automated Rollback

```bash
# Create rollback checkpoint before migration
security-migrate checkpoint create --name "pre-v2.0-migration"

# Perform migration
security-migrate apply --version 2.0.0

# If issues occur, rollback
security-migrate rollback --to-checkpoint "pre-v2.0-migration"
```

### Manual Rollback Steps

1. **Stop Application**
   ```bash
   # Docker
   docker-compose down
   
   # Kubernetes
   kubectl scale deployment security-framework --replicas=0
   
   # Systemd
   sudo systemctl stop security-framework
   ```

2. **Restore Database**
   ```bash
   # SQLite
   cp /backup/security_backup.db /app/data/security.db
   
   # Or restore from SQL script
   sqlite3 /app/data/security.db < /backup/pre_migration_dump.sql
   ```

3. **Restore Configuration**
   ```bash
   cp /backup/appsettings.json /app/appsettings.json
   cp -r /backup/patterns/* /app/patterns/
   ```

4. **Deploy Previous Version**
   ```bash
   # Docker
   docker pull myregistry/security-framework:1.5.0
   docker-compose up -d
   
   # Manual deployment
   dotnet restore SecurityFramework.sln
   dotnet build -c Release
   dotnet run --project src/SecurityFramework.Core
   ```

5. **Validate Rollback**
   ```bash
   # Health check
   curl -f http://localhost:8080/health
   
   # Functional test
   curl -X POST http://localhost:8080/api/security/assess \
        -H "Content-Type: application/json" \
        -d '{"ipAddress": "192.168.1.1"}'
   ```

## Migration Tools

### Command-Line Migration Tool

```bash
# Install
dotnet tool install --global SecurityFramework.Tools.Migration

# Check migration requirements
security-migrate check --from 1.5.0 --to 2.0.0

# Preview migration changes
security-migrate preview --config appsettings.json --version 2.0.0

# Execute migration
security-migrate apply --version 2.0.0 --backup

# Validate migration
security-migrate validate --version 2.0.0
```

### PowerShell Migration Module

```powershell
# Install PowerShell module
Install-Module SecurityFramework.Migration

# Import module
Import-Module SecurityFramework.Migration

# Start migration wizard
Start-SecurityFrameworkMigration -FromVersion "1.5.0" -ToVersion "2.0.0"

# Batch migration for multiple environments
$environments = @("staging", "production")
foreach ($env in $environments) {
    Invoke-SecurityFrameworkMigration -Environment $env -Version "2.0.0"
}
```

### Migration Health Checks

```csharp
public class MigrationHealthCheck : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Verify database schema version
            var schemaVersion = await _migrationService.GetSchemaVersionAsync();
            var expectedVersion = _configuration.GetValue<string>("Migration:ExpectedSchemaVersion");
            
            if (schemaVersion != expectedVersion)
            {
                return HealthCheckResult.Degraded($"Schema version mismatch. Expected: {expectedVersion}, Actual: {schemaVersion}");
            }
            
            // Verify configuration compatibility
            var configCompatibility = await _migrationService.ValidateConfigurationAsync();
            if (!configCompatibility.IsValid)
            {
                return HealthCheckResult.Unhealthy($"Configuration compatibility issues: {string.Join(", ", configCompatibility.Issues)}");
            }
            
            // Verify data integrity
            var dataIntegrity = await _migrationService.ValidateDataIntegrityAsync();
            if (!dataIntegrity.IsValid)
            {
                return HealthCheckResult.Unhealthy($"Data integrity issues detected: {string.Join(", ", dataIntegrity.Issues)}");
            }
            
            return HealthCheckResult.Healthy("Migration completed successfully");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy($"Migration health check failed: {ex.Message}");
        }
    }
}
```

### Best Practices

1. **Always backup before migration**
2. **Test migrations in staging environment first**
3. **Use feature flags for gradual rollout**
4. **Monitor application health during and after migration**
5. **Have rollback plan ready and tested**
6. **Document custom migration steps**
7. **Validate data integrity after migration**
8. **Update monitoring and alerting for new features**

This migration guide provides comprehensive coverage for upgrading the Security Framework across versions while maintaining data integrity and minimizing downtime.