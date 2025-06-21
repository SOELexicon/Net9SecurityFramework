using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SecurityFramework.Annotations;

/// <summary>
/// Validates that a parameter contains a properly formatted resource ID
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class ResourceIdAttribute : ValidationAttribute
{
    /// <summary>
    /// Type of resource ID format to validate
    /// </summary>
    public ResourceIdFormat Format { get; set; } = ResourceIdFormat.Auto;

    /// <summary>
    /// Minimum length for the resource ID
    /// </summary>
    public int MinLength { get; set; } = 1;

    /// <summary>
    /// Maximum length for the resource ID
    /// </summary>
    public int MaxLength { get; set; } = 50;

    /// <summary>
    /// Whether to allow null or empty values
    /// </summary>
    public bool AllowEmpty { get; set; } = false;

    /// <summary>
    /// Custom regex pattern for validation
    /// </summary>
    public string? CustomPattern { get; set; }

    /// <summary>
    /// Resource type for more specific validation
    /// </summary>
    public string? ResourceType { get; set; }

    public ResourceIdAttribute()
    {
        ErrorMessage = "Invalid resource ID format";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
        {
            return AllowEmpty ? ValidationResult.Success : new ValidationResult("Resource ID cannot be null");
        }

        var idString = value.ToString();
        if (string.IsNullOrWhiteSpace(idString))
        {
            return AllowEmpty ? ValidationResult.Success : new ValidationResult("Resource ID cannot be empty");
        }

        // Check length constraints
        if (idString.Length < MinLength)
        {
            return new ValidationResult($"Resource ID must be at least {MinLength} characters long");
        }

        if (idString.Length > MaxLength)
        {
            return new ValidationResult($"Resource ID cannot exceed {MaxLength} characters");
        }

        // Use custom pattern if provided
        if (!string.IsNullOrEmpty(CustomPattern))
        {
            if (!Regex.IsMatch(idString, CustomPattern))
            {
                return new ValidationResult($"Resource ID does not match the required pattern");
            }
            return ValidationResult.Success;
        }

        // Validate based on format
        var validationError = Format switch
        {
            ResourceIdFormat.Integer => ValidateIntegerFormat(idString),
            ResourceIdFormat.Guid => ValidateGuidFormat(idString),
            ResourceIdFormat.Alphanumeric => ValidateAlphanumericFormat(idString),
            ResourceIdFormat.Base64 => ValidateBase64Format(idString),
            ResourceIdFormat.Uuid => ValidateUuidFormat(idString),
            ResourceIdFormat.ObjectId => ValidateObjectIdFormat(idString),
            ResourceIdFormat.Auto => ValidateAutoFormat(idString),
            _ => null
        };

        return validationError;
    }

    private ValidationResult? ValidateIntegerFormat(string id)
    {
        if (!long.TryParse(id, out var numericId))
        {
            return new ValidationResult("Resource ID must be a valid integer");
        }

        if (numericId <= 0)
        {
            return new ValidationResult("Resource ID must be a positive integer");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateGuidFormat(string id)
    {
        if (!Guid.TryParse(id, out _))
        {
            return new ValidationResult("Resource ID must be a valid GUID");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateAlphanumericFormat(string id)
    {
        if (!Regex.IsMatch(id, @"^[a-zA-Z0-9]+$"))
        {
            return new ValidationResult("Resource ID must contain only alphanumeric characters");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateBase64Format(string id)
    {
        try
        {
            Convert.FromBase64String(id);
            return ValidationResult.Success;
        }
        catch
        {
            return new ValidationResult("Resource ID must be valid Base64 format");
        }
    }

    private ValidationResult? ValidateUuidFormat(string id)
    {
        // UUID format: 8-4-4-4-12 hexadecimal digits
        var uuidPattern = @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
        if (!Regex.IsMatch(id, uuidPattern))
        {
            return new ValidationResult("Resource ID must be a valid UUID format");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateObjectIdFormat(string id)
    {
        // MongoDB ObjectId format: 24 hexadecimal characters
        if (!Regex.IsMatch(id, @"^[0-9a-fA-F]{24}$"))
        {
            return new ValidationResult("Resource ID must be a valid ObjectId format (24 hex characters)");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateAutoFormat(string id)
    {
        // Try different formats in order of preference
        if (Guid.TryParse(id, out _))
            return ValidationResult.Success;

        if (long.TryParse(id, out var numericId) && numericId > 0)
            return ValidationResult.Success;

        if (Regex.IsMatch(id, @"^[0-9a-fA-F]{24}$"))
            return ValidationResult.Success;

        if (Regex.IsMatch(id, @"^[a-zA-Z0-9_-]+$"))
            return ValidationResult.Success;

        return new ValidationResult("Resource ID format is not recognized");
    }
}

/// <summary>
/// Resource ID format types
/// </summary>
public enum ResourceIdFormat
{
    /// <summary>
    /// Automatically detect format (GUID, integer, ObjectId, or alphanumeric)
    /// </summary>
    Auto,

    /// <summary>
    /// Positive integer (1, 2, 3, ...)
    /// </summary>
    Integer,

    /// <summary>
    /// GUID format (00000000-0000-0000-0000-000000000000)
    /// </summary>
    Guid,

    /// <summary>
    /// Alphanumeric characters only
    /// </summary>
    Alphanumeric,

    /// <summary>
    /// Base64 encoded string
    /// </summary>
    Base64,

    /// <summary>
    /// UUID format with hyphens
    /// </summary>
    Uuid,

    /// <summary>
    /// MongoDB ObjectId (24 hex characters)
    /// </summary>
    ObjectId
}

/// <summary>
/// Validates that parameter values are within expected ranges to prevent enumeration attacks
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AntiEnumerationAttribute : ValidationAttribute
{
    /// <summary>
    /// Maximum allowed numeric value for resource IDs
    /// </summary>
    public long MaxNumericValue { get; set; } = long.MaxValue;

    /// <summary>
    /// Minimum allowed numeric value for resource IDs
    /// </summary>
    public long MinNumericValue { get; set; } = 1;

    /// <summary>
    /// Whether to allow sequential access patterns
    /// </summary>
    public bool AllowSequentialAccess { get; set; } = true;

    /// <summary>
    /// Maximum rate of requests per minute for this parameter
    /// </summary>
    public int MaxRequestsPerMinute { get; set; } = 60;

    /// <summary>
    /// Whether to randomize error messages to prevent information disclosure
    /// </summary>
    public bool RandomizeErrorMessages { get; set; } = true;

    public AntiEnumerationAttribute()
    {
        ErrorMessage = "Parameter value is not allowed";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var valueString = value.ToString();
        if (string.IsNullOrWhiteSpace(valueString))
            return ValidationResult.Success;

        // Check numeric ranges if the value is numeric
        if (long.TryParse(valueString, out var numericValue))
        {
            if (numericValue < MinNumericValue || numericValue > MaxNumericValue)
            {
                var errorMessage = RandomizeErrorMessages 
                    ? GetRandomizedErrorMessage() 
                    : $"Value must be between {MinNumericValue} and {MaxNumericValue}";
                
                return new ValidationResult(errorMessage);
            }

            // Check for potentially suspicious enumeration patterns
            if (!AllowSequentialAccess && IsSuspiciousSequentialPattern(numericValue))
            {
                var errorMessage = RandomizeErrorMessages 
                    ? GetRandomizedErrorMessage() 
                    : "Sequential access pattern detected";
                
                return new ValidationResult(errorMessage);
            }
        }

        // Additional validation could be added here for rate limiting
        // This would require integration with a caching/rate limiting service

        return ValidationResult.Success;
    }

    private static bool IsSuspiciousSequentialPattern(long value)
    {
        // This is a simplified check - in production, you'd track request patterns
        // For now, we'll flag very obvious sequential patterns
        return value > 0 && value <= 1000 && value % 10 == 0; // Multiples of 10 up to 1000
    }

    private static string GetRandomizedErrorMessage()
    {
        var messages = new[]
        {
            "Invalid parameter value",
            "Parameter validation failed",
            "Value not found",
            "Access denied",
            "Parameter out of range",
            "Invalid request parameter"
        };

        var random = new Random();
        return messages[random.Next(messages.Length)];
    }
}

/// <summary>
/// Validates user authorization for accessing specific resource parameters
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class RequireResourceAuthorizationAttribute : ValidationAttribute
{
    /// <summary>
    /// Resource type for authorization check
    /// </summary>
    public string ResourceType { get; set; } = "";

    /// <summary>
    /// Required permission level
    /// </summary>
    public string Permission { get; set; } = "read";

    /// <summary>
    /// Whether to allow access for resource owners
    /// </summary>
    public bool AllowOwnerAccess { get; set; } = true;

    /// <summary>
    /// Whether to allow access for administrators
    /// </summary>
    public bool AllowAdminAccess { get; set; } = true;

    /// <summary>
    /// Custom authorization policy name
    /// </summary>
    public string? AuthorizationPolicy { get; set; }

    public RequireResourceAuthorizationAttribute()
    {
        ErrorMessage = "You are not authorized to access this resource";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        // This is a placeholder for authorization logic
        // In a real implementation, this would integrate with your authorization system
        
        // Get user context from validation context
        var userContext = GetUserContext(validationContext);
        if (userContext == null)
        {
            return new ValidationResult("User context not available for authorization");
        }

        // Check if user has required permissions
        if (!HasRequiredPermission(userContext, value.ToString(), ResourceType, Permission))
        {
            return new ValidationResult(ErrorMessage);
        }

        return ValidationResult.Success;
    }

    private static object? GetUserContext(ValidationContext validationContext)
    {
        // This would extract user context from the validation context
        // Implementation depends on your authentication/authorization framework
        return validationContext.Items.TryGetValue("UserContext", out var context) ? context : null;
    }

    private bool HasRequiredPermission(object userContext, string? resourceId, string resourceType, string permission)
    {
        // This would implement actual authorization logic
        // For now, return true to allow the validation to pass
        // In production, this would check:
        // 1. User permissions
        // 2. Resource ownership
        // 3. Role-based access
        // 4. Custom authorization policies
        
        return true; // Placeholder - implement actual authorization logic
    }
}

/// <summary>
/// Validates that parameter combinations don't indicate IDOR attack patterns
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
public class IDORProtectionAttribute : ValidationAttribute
{
    /// <summary>
    /// Parameters to validate for IDOR patterns
    /// </summary>
    public string[] ParameterNames { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether to check for user context consistency
    /// </summary>
    public bool CheckUserContext { get; set; } = true;

    /// <summary>
    /// Whether to validate resource ownership
    /// </summary>
    public bool ValidateOwnership { get; set; } = true;

    /// <summary>
    /// Maximum number of different resources that can be accessed in one request
    /// </summary>
    public int MaxResourceCount { get; set; } = 1;

    public IDORProtectionAttribute()
    {
        ErrorMessage = "Request contains potential IDOR attack patterns";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        // Get parameter values to check
        var parameterValues = new Dictionary<string, object?>();
        var objectType = value.GetType();

        foreach (var paramName in ParameterNames)
        {
            var property = objectType.GetProperty(paramName);
            if (property != null)
            {
                parameterValues[paramName] = property.GetValue(value);
            }
        }

        // Check for suspicious parameter patterns
        if (HasSuspiciousParameterPatterns(parameterValues))
        {
            return new ValidationResult("Suspicious parameter access pattern detected");
        }

        // Check user context if required
        if (CheckUserContext && !ValidateUserContextConsistency(validationContext, parameterValues))
        {
            return new ValidationResult("User context validation failed");
        }

        // Check resource ownership if required
        if (ValidateOwnership && !ValidateResourceOwnership(validationContext, parameterValues))
        {
            return new ValidationResult("Resource ownership validation failed");
        }

        return ValidationResult.Success;
    }

    private static bool HasSuspiciousParameterPatterns(Dictionary<string, object?> parameters)
    {
        // Check for sequential numeric IDs
        var numericIds = parameters.Values
            .Where(v => v != null && long.TryParse(v.ToString(), out _))
            .Select(v => long.Parse(v!.ToString()!))
            .OrderBy(id => id)
            .ToList();

        if (numericIds.Count > 1)
        {
            // Check if IDs are sequential (potential enumeration)
            for (int i = 1; i < numericIds.Count; i++)
            {
                if (numericIds[i] - numericIds[i - 1] == 1)
                {
                    return true; // Sequential IDs detected
                }
            }
        }

        return false;
    }

    private static bool ValidateUserContextConsistency(ValidationContext validationContext, Dictionary<string, object?> parameters)
    {
        // Placeholder for user context validation
        // This would check that the user has consistent access to all referenced resources
        return true;
    }

    private static bool ValidateResourceOwnership(ValidationContext validationContext, Dictionary<string, object?> parameters)
    {
        // Placeholder for ownership validation
        // This would verify that the user owns or has access to all referenced resources
        return true;
    }
}

/// <summary>
/// Validates parameter format for specific data types with security considerations
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class SecureFormatAttribute : ValidationAttribute
{
    /// <summary>
    /// Data format to validate
    /// </summary>
    public SecureDataFormat Format { get; set; } = SecureDataFormat.General;

    /// <summary>
    /// Whether to apply strict validation rules
    /// </summary>
    public bool StrictMode { get; set; } = true;

    /// <summary>
    /// Maximum allowed length
    /// </summary>
    public int MaxLength { get; set; } = 1000;

    public SecureFormatAttribute()
    {
        ErrorMessage = "Parameter format is not secure or valid";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString();
        if (string.IsNullOrWhiteSpace(input))
            return ValidationResult.Success;

        if (input.Length > MaxLength)
        {
            return new ValidationResult($"Input exceeds maximum length of {MaxLength} characters");
        }

        return Format switch
        {
            SecureDataFormat.Email => ValidateEmailFormat(input),
            SecureDataFormat.PhoneNumber => ValidatePhoneFormat(input),
            SecureDataFormat.CreditCard => ValidateCreditCardFormat(input),
            SecureDataFormat.SSN => ValidateSSNFormat(input),
            SecureDataFormat.PostalCode => ValidatePostalCodeFormat(input),
            SecureDataFormat.Username => ValidateUsernameFormat(input),
            SecureDataFormat.Password => ValidatePasswordFormat(input),
            SecureDataFormat.Url => ValidateUrlFormat(input),
            SecureDataFormat.FileName => ValidateFileNameFormat(input),
            SecureDataFormat.General => ValidateGeneralFormat(input),
            _ => ValidationResult.Success
        };
    }

    private ValidationResult? ValidateEmailFormat(string email)
    {
        var emailPattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
        if (!Regex.IsMatch(email, emailPattern))
        {
            return new ValidationResult("Invalid email format");
        }

        // Check for suspicious patterns
        if (email.Contains("..") || email.StartsWith(".") || email.EndsWith("."))
        {
            return new ValidationResult("Email contains suspicious patterns");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidatePhoneFormat(string phone)
    {
        var cleanPhone = Regex.Replace(phone, @"[^\d]", "");
        if (cleanPhone.Length < 10 || cleanPhone.Length > 15)
        {
            return new ValidationResult("Phone number must be between 10 and 15 digits");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateCreditCardFormat(string creditCard)
    {
        // This should never store actual credit card numbers
        return new ValidationResult("Credit card numbers should not be stored in parameters");
    }

    private ValidationResult? ValidateSSNFormat(string ssn)
    {
        // SSN should not be passed as URL parameters
        return new ValidationResult("SSN should not be passed as parameters for security reasons");
    }

    private ValidationResult? ValidatePostalCodeFormat(string postalCode)
    {
        // Basic validation for various postal code formats
        if (!Regex.IsMatch(postalCode, @"^[a-zA-Z0-9\s-]{3,10}$"))
        {
            return new ValidationResult("Invalid postal code format");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateUsernameFormat(string username)
    {
        if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_.-]{3,30}$"))
        {
            return new ValidationResult("Username must be 3-30 characters and contain only letters, numbers, dots, hyphens, and underscores");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidatePasswordFormat(string password)
    {
        // Passwords should never be in URL parameters
        return new ValidationResult("Passwords should not be passed as parameters");
    }

    private ValidationResult? ValidateUrlFormat(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return new ValidationResult("Invalid URL format");
        }

        // Check for suspicious protocols
        var allowedSchemes = new[] { "http", "https", "ftp", "ftps" };
        if (!allowedSchemes.Contains(uri.Scheme.ToLowerInvariant()))
        {
            return new ValidationResult("URL scheme is not allowed");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateFileNameFormat(string fileName)
    {
        if (fileName.Contains("..") || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return new ValidationResult("Invalid file name format");
        }

        return ValidationResult.Success;
    }

    private ValidationResult? ValidateGeneralFormat(string input)
    {
        // Check for common injection patterns
        var suspiciousPatterns = new[]
        {
            @"<script", @"javascript:", @"vbscript:", @"on\w+\s*=",
            @"union\s+select", @"drop\s+table", @"\bexec\s*\(",
            @"\.\.[\\/]", @"%2e%2e%2f", @"%2e%2e%5c"
        };

        foreach (var pattern in suspiciousPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                return new ValidationResult($"Input contains suspicious pattern: {pattern}");
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Secure data format types
/// </summary>
public enum SecureDataFormat
{
    General,
    Email,
    PhoneNumber,
    CreditCard,
    SSN,
    PostalCode,
    Username,
    Password,
    Url,
    FileName
}