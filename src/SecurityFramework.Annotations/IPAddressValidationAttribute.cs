using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.NetworkInformation;

namespace SecurityFramework.Annotations;

/// <summary>
/// Validates that a string is a valid IP address
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class IPAddressValidationAttribute : ValidationAttribute
{
    /// <summary>
    /// IP address family to validate (Any, IPv4, IPv6)
    /// </summary>
    public IPAddressFamily AddressFamily { get; set; } = IPAddressFamily.Any;

    /// <summary>
    /// Whether to allow loopback addresses (127.0.0.1, ::1)
    /// </summary>
    public bool AllowLoopback { get; set; } = true;

    /// <summary>
    /// Whether to allow private/internal network addresses
    /// </summary>
    public bool AllowPrivate { get; set; } = true;

    /// <summary>
    /// Whether to allow multicast addresses
    /// </summary>
    public bool AllowMulticast { get; set; } = false;

    /// <summary>
    /// Whether to allow IPv6 link-local addresses
    /// </summary>
    public bool AllowLinkLocal { get; set; } = true;

    /// <summary>
    /// Custom blocked IP ranges (CIDR notation)
    /// </summary>
    public string[]? BlockedRanges { get; set; }

    /// <summary>
    /// Custom allowed IP ranges (CIDR notation) - if specified, only these ranges are allowed
    /// </summary>
    public string[]? AllowedRanges { get; set; }

    public IPAddressValidationAttribute()
    {
        ErrorMessage = "Invalid IP address format or value";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var ipString = value.ToString();
        if (string.IsNullOrWhiteSpace(ipString))
            return ValidationResult.Success;

        // Parse IP address
        if (!IPAddress.TryParse(ipString, out var ipAddress))
        {
            return new ValidationResult($"'{ipString}' is not a valid IP address format");
        }

        // Validate address family
        var validationError = ValidateAddressFamily(ipAddress);
        if (validationError != null)
            return validationError;

        // Validate address type restrictions
        validationError = ValidateAddressType(ipAddress);
        if (validationError != null)
            return validationError;

        // Validate against blocked ranges
        validationError = ValidateBlockedRanges(ipAddress);
        if (validationError != null)
            return validationError;

        // Validate against allowed ranges (if specified)
        validationError = ValidateAllowedRanges(ipAddress);
        if (validationError != null)
            return validationError;

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateAddressFamily(IPAddress ipAddress)
    {
        return AddressFamily switch
        {
            IPAddressFamily.IPv4 when ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork =>
                new ValidationResult("Only IPv4 addresses are allowed"),
            IPAddressFamily.IPv6 when ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 =>
                new ValidationResult("Only IPv6 addresses are allowed"),
            _ => null
        };
    }

    private ValidationResult? ValidateAddressType(IPAddress ipAddress)
    {
        // Check loopback
        if (!AllowLoopback && IPAddress.IsLoopback(ipAddress))
        {
            return new ValidationResult("Loopback addresses are not allowed");
        }

        // Check private addresses
        if (!AllowPrivate && IsPrivateAddress(ipAddress))
        {
            return new ValidationResult("Private network addresses are not allowed");
        }

        // Check multicast
        if (!AllowMulticast && IsMulticastAddress(ipAddress))
        {
            return new ValidationResult("Multicast addresses are not allowed");
        }

        // Check IPv6 link-local
        if (!AllowLinkLocal && IsLinkLocalAddress(ipAddress))
        {
            return new ValidationResult("Link-local addresses are not allowed");
        }

        return null;
    }

    private ValidationResult? ValidateBlockedRanges(IPAddress ipAddress)
    {
        if (BlockedRanges == null || BlockedRanges.Length == 0)
            return null;

        foreach (var range in BlockedRanges)
        {
            if (IsInRange(ipAddress, range))
            {
                return new ValidationResult($"IP address is in blocked range: {range}");
            }
        }

        return null;
    }

    private ValidationResult? ValidateAllowedRanges(IPAddress ipAddress)
    {
        if (AllowedRanges == null || AllowedRanges.Length == 0)
            return null;

        foreach (var range in AllowedRanges)
        {
            if (IsInRange(ipAddress, range))
            {
                return null; // Found in allowed range
            }
        }

        return new ValidationResult("IP address is not in any allowed range");
    }

    private static bool IsPrivateAddress(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ipAddress.GetAddressBytes();
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168);
        }
        
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // IPv6 private ranges: fc00::/7, fe80::/10
            var bytes = ipAddress.GetAddressBytes();
            return (bytes[0] & 0xFE) == 0xFC || // fc00::/7
                   (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80); // fe80::/10
        }

        return false;
    }

    private static bool IsMulticastAddress(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ipAddress.GetAddressBytes();
            return bytes[0] >= 224 && bytes[0] <= 239; // 224.0.0.0/4
        }
        
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var bytes = ipAddress.GetAddressBytes();
            return bytes[0] == 0xFF; // ff00::/8
        }

        return false;
    }

    private static bool IsLinkLocalAddress(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ipAddress.GetAddressBytes();
            return bytes[0] == 169 && bytes[1] == 254; // 169.254.0.0/16
        }
        
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var bytes = ipAddress.GetAddressBytes();
            return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80; // fe80::/10
        }

        return false;
    }

    private static bool IsInRange(IPAddress ipAddress, string cidrRange)
    {
        try
        {
            // Simple CIDR parsing - in production, use a dedicated library
            var parts = cidrRange.Split('/');
            if (parts.Length != 2)
                return false;

            if (!IPAddress.TryParse(parts[0], out var networkAddress))
                return false;

            if (!int.TryParse(parts[1], out var prefixLength))
                return false;

            // Convert to byte arrays for comparison
            var networkBytes = networkAddress.GetAddressBytes();
            var addressBytes = ipAddress.GetAddressBytes();

            if (networkBytes.Length != addressBytes.Length)
                return false;

            // Calculate mask
            var maskBits = prefixLength;
            for (int i = 0; i < networkBytes.Length; i++)
            {
                var mask = maskBits >= 8 ? 0xFF : maskBits > 0 ? (0xFF << (8 - maskBits)) & 0xFF : 0x00;
                
                if ((networkBytes[i] & mask) != (addressBytes[i] & mask))
                    return false;

                maskBits = Math.Max(0, maskBits - 8);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// IP address family for validation
/// </summary>
public enum IPAddressFamily
{
    /// <summary>
    /// Allow both IPv4 and IPv6
    /// </summary>
    Any,

    /// <summary>
    /// Allow only IPv4 addresses
    /// </summary>
    IPv4,

    /// <summary>
    /// Allow only IPv6 addresses
    /// </summary>
    IPv6
}

/// <summary>
/// Validates that a string is a valid CIDR notation (IP/prefix)
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class CIDRValidationAttribute : ValidationAttribute
{
    /// <summary>
    /// IP address family to validate
    /// </summary>
    public IPAddressFamily AddressFamily { get; set; } = IPAddressFamily.Any;

    public CIDRValidationAttribute()
    {
        ErrorMessage = "Invalid CIDR notation format";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var cidrString = value.ToString();
        if (string.IsNullOrWhiteSpace(cidrString))
            return ValidationResult.Success;

        var parts = cidrString.Split('/');
        if (parts.Length != 2)
        {
            return new ValidationResult("CIDR notation must be in format 'IP/prefix'");
        }

        // Validate IP address part
        if (!IPAddress.TryParse(parts[0], out var ipAddress))
        {
            return new ValidationResult($"'{parts[0]}' is not a valid IP address");
        }

        // Validate prefix length
        if (!int.TryParse(parts[1], out var prefixLength))
        {
            return new ValidationResult($"'{parts[1]}' is not a valid prefix length");
        }

        // Validate prefix length range based on address family
        var isIPv4 = ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var isIPv6 = ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

        if (isIPv4 && (prefixLength < 0 || prefixLength > 32))
        {
            return new ValidationResult("IPv4 prefix length must be between 0 and 32");
        }

        if (isIPv6 && (prefixLength < 0 || prefixLength > 128))
        {
            return new ValidationResult("IPv6 prefix length must be between 0 and 128");
        }

        // Validate address family if specified
        var familyError = AddressFamily switch
        {
            IPAddressFamily.IPv4 when !isIPv4 => new ValidationResult("Only IPv4 CIDR notation is allowed"),
            IPAddressFamily.IPv6 when !isIPv6 => new ValidationResult("Only IPv6 CIDR notation is allowed"),
            _ => null
        };

        return familyError;
    }
}

/// <summary>
/// Validates that an IP address is not in any blocked lists or ranges
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class IPAddressNotBlockedAttribute : ValidationAttribute
{
    /// <summary>
    /// Blocked IP addresses (exact matches)
    /// </summary>
    public string[]? BlockedAddresses { get; set; }

    /// <summary>
    /// Blocked IP ranges in CIDR notation
    /// </summary>
    public string[]? BlockedRanges { get; set; }

    /// <summary>
    /// Whether to check against known malicious IP databases
    /// </summary>
    public bool CheckMaliciousLists { get; set; } = false;

    public IPAddressNotBlockedAttribute()
    {
        ErrorMessage = "IP address is blocked";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var ipString = value.ToString();
        if (string.IsNullOrWhiteSpace(ipString))
            return ValidationResult.Success;

        if (!IPAddress.TryParse(ipString, out var ipAddress))
        {
            return new ValidationResult("Invalid IP address format");
        }

        // Check exact matches
        if (BlockedAddresses?.Contains(ipString) == true)
        {
            return new ValidationResult($"IP address {ipString} is explicitly blocked");
        }

        // Check blocked ranges
        if (BlockedRanges != null)
        {
            foreach (var range in BlockedRanges)
            {
                if (IsInRange(ipAddress, range))
                {
                    return new ValidationResult($"IP address {ipString} is in blocked range {range}");
                }
            }
        }

        // Optional: Check against malicious IP lists
        if (CheckMaliciousLists)
        {
            // This would integrate with external threat intelligence services
            // For now, we'll just check some basic patterns
            if (IsKnownMaliciousPattern(ipString))
            {
                return new ValidationResult($"IP address {ipString} matches known malicious patterns");
            }
        }

        return ValidationResult.Success;
    }

    private static bool IsInRange(IPAddress ipAddress, string cidrRange)
    {
        // Same implementation as in IPAddressValidationAttribute
        try
        {
            var parts = cidrRange.Split('/');
            if (parts.Length != 2)
                return false;

            if (!IPAddress.TryParse(parts[0], out var networkAddress))
                return false;

            if (!int.TryParse(parts[1], out var prefixLength))
                return false;

            var networkBytes = networkAddress.GetAddressBytes();
            var addressBytes = ipAddress.GetAddressBytes();

            if (networkBytes.Length != addressBytes.Length)
                return false;

            var maskBits = prefixLength;
            for (int i = 0; i < networkBytes.Length; i++)
            {
                var mask = maskBits >= 8 ? 0xFF : maskBits > 0 ? (0xFF << (8 - maskBits)) & 0xFF : 0x00;
                
                if ((networkBytes[i] & mask) != (addressBytes[i] & mask))
                    return false;

                maskBits = Math.Max(0, maskBits - 8);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsKnownMaliciousPattern(string ipAddress)
    {
        // Basic patterns for known bad ranges
        // In production, this would check against threat intelligence feeds
        var maliciousPatterns = new[]
        {
            "0.0.0.0",           // Invalid
            "255.255.255.255",   // Broadcast
            "127.",              // Loopback (if not allowed)
        };

        return maliciousPatterns.Any(pattern => ipAddress.StartsWith(pattern));
    }
}