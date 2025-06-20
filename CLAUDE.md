# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a .NET 9 Intelligent Security Framework project for building a comprehensive security solution that provides IP-based threat detection, behavioral analysis, parameter jacking prevention, and adaptive security responses using machine learning-inspired scoring algorithms with EF Core in-memory database storage.

## Project Status

This project is currently in the planning/design phase. The directory contains only the project scope document (`security-framework-scope (1).md`) which defines the complete architecture and requirements for the security framework.

## Key Architecture Components

### Technology Stack
- **.NET 9**: Core framework
- **EF Core 9**: In-memory database provider with SQLite persistence
- **ASP.NET Core**: Middleware integration
- **SignalR**: Real-time communications (optional)
- **WebSockets**: Low-level real-time support (optional)
- **ML.NET**: Optional machine learning for advanced scoring
- **Redis**: Optional distributed cache and SignalR backplane

### Core Features
1. **IP Intelligence System**: Historical tracking, behavioral profiling, trust building
2. **Threat Detection**: Pattern-based detection, parameter jacking prevention, blocklist management
3. **Real-time Monitoring**: Optional SignalR/WebSocket integration for live dashboard
4. **Data Persistence**: Hybrid in-memory + SQLite storage with configurable persistence
5. **Scoring Engine**: Machine learning-inspired threat scoring with multiple algorithms
6. **Pattern Management**: JSON-based pattern templates with hot-reload capability

### Project Structure (Planned)

```
SecurityFramework/
├── src/
│   ├── SecurityFramework.Core/          # Core abstractions, models, extensions
│   ├── SecurityFramework.Data/          # EF Core context, repositories, migrations
│   ├── SecurityFramework.Services/      # Business logic, detection engines
│   ├── SecurityFramework.Middleware/    # ASP.NET Core middleware
│   ├── SecurityFramework.RealTime/      # Optional SignalR/WebSocket support
│   └── SecurityFramework.ML/            # Optional machine learning features
├── tests/                               # Unit, integration, performance tests
├── samples/                            # Example implementations
├── patterns/                           # Threat pattern templates (JSON)
└── docs/                              # Documentation
```

## Development Commands

Since this project is in the planning phase, no build commands are available yet. Once implementation begins, typical .NET commands will be:

- **Build**: `dotnet build`
- **Test**: `dotnet test`
- **Run**: `dotnet run`
- **Package**: `dotnet pack`

## Key Design Principles

1. **Performance First**: Target < 1ms IP assessment with in-memory storage
2. **Modular Architecture**: Optional features can be completely disabled
3. **Real-time Optional**: SignalR/WebSocket features are entirely optional and configurable
4. **Data Annotations**: Comprehensive validation using .NET data annotations
5. **Pattern-Based**: JSON pattern templates for flexible threat detection
6. **Defensive Security Focus**: Built specifically for defensive security applications

## Security Considerations

This framework is designed specifically for defensive security purposes:
- IP-based threat detection and scoring
- Parameter jacking (IDOR) prevention
- Pattern-based malicious request detection
- Real-time security monitoring and alerting
- Adaptive security response mechanisms

## Configuration Philosophy

The framework uses a highly configurable approach where features can be enabled/disabled:
- Core IP tracking is always available
- Real-time features (SignalR/WebSocket) are completely optional
- ML features require additional packages
- Persistence can be in-memory only or include SQLite backing

## Implementation Notes

When implementing this framework:
1. Start with core IP tracking and basic threat detection
2. Implement pattern matching system with JSON templates
3. Add middleware integration for ASP.NET Core
4. Optionally add real-time features if needed
5. Follow the comprehensive data annotation strategy outlined in the scope
6. Implement graduated response system (allow/challenge/restrict/block)
7. Focus on sub-millisecond response times for IP assessments