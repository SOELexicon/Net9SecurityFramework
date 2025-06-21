using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SecurityFramework.Annotations;

/// <summary>
/// Validates that input does not contain SQL injection patterns
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class NoSQLInjectionAttribute : ValidationAttribute
{
    /// <summary>
    /// Whether to perform strict validation (more patterns)
    /// </summary>
    public bool StrictMode { get; set; } = false;

    /// <summary>
    /// Whether validation is case-sensitive
    /// </summary>
    public bool CaseSensitive { get; set; } = false;

    /// <summary>
    /// Custom patterns to check (in addition to built-in patterns)
    /// </summary>
    public string[]? CustomPatterns { get; set; }

    private static readonly string[] BasicSQLPatterns = {
        @"\b(union\s+select)\b",
        @"\b(drop\s+table)\b",
        @"\b(delete\s+from)\b",
        @"\b(insert\s+into)\b",
        @"\b(update\s+set)\b",
        @"('.*'.*=.*'.*')",
        @"(;\s*--)",
        @"(/\*.*\*/)",
        @"\b(exec\s*\()",
        @"\b(execute\s*\()"
    };

    private static readonly string[] StrictSQLPatterns = {
        @"\b(alter\s+table)\b",
        @"\b(create\s+table)\b",
        @"\b(grant\s+select)\b",
        @"\b(revoke\s+select)\b",
        @"(\bor\b.*=.*)",
        @"(\band\b.*=.*)",
        @"(--.*$)",
        @"(#.*$)",
        @"\b(waitfor\s+delay)\b",
        @"\b(sp_executesql)\b",
        @"\b(xp_cmdshell)\b",
        @"(\bchar\s*\(\s*\d+\s*\))",
        @"(\bascii\s*\(\s*substr)",
        @"(\bhaving\s+\d+\s*=\s*\d+)",
        @"(\bgroup\s+by\s+\d+)",
        @"(\border\s+by\s+\d+)"
    };

    public NoSQLInjectionAttribute()
    {
        ErrorMessage = "Input contains potential SQL injection patterns";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString();
        if (string.IsNullOrWhiteSpace(input))
            return ValidationResult.Success;

        var regexOptions = CaseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase;

        // Check basic patterns
        foreach (var pattern in BasicSQLPatterns)
        {
            if (Regex.IsMatch(input, pattern, regexOptions))
            {
                return new ValidationResult($"Input contains SQL injection pattern: {pattern}");
            }
        }

        // Check strict patterns if enabled
        if (StrictMode)
        {
            foreach (var pattern in StrictSQLPatterns)
            {
                if (Regex.IsMatch(input, pattern, regexOptions))
                {
                    return new ValidationResult($"Input contains SQL injection pattern: {pattern}");
                }
            }
        }

        // Check custom patterns
        if (CustomPatterns != null)
        {
            foreach (var pattern in CustomPatterns)
            {
                if (Regex.IsMatch(input, pattern, regexOptions))
                {
                    return new ValidationResult($"Input contains custom security pattern: {pattern}");
                }
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that input does not contain XSS (Cross-Site Scripting) patterns
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class NoXSSAttribute : ValidationAttribute
{
    /// <summary>
    /// Whether to perform strict validation
    /// </summary>
    public bool StrictMode { get; set; } = false;

    /// <summary>
    /// Whether to allow basic HTML tags
    /// </summary>
    public bool AllowBasicHtml { get; set; } = false;

    /// <summary>
    /// Allowed HTML tags (if AllowBasicHtml is true)
    /// </summary>
    public string[]? AllowedTags { get; set; }

    private static readonly string[] XSSPatterns = {
        @"<script[^>]*>.*?</script>",
        @"<script[^>]*>",
        @"</script>",
        @"javascript:",
        @"vbscript:",
        @"on\w+\s*=",
        @"<iframe[^>]*>",
        @"<object[^>]*>",
        @"<embed[^>]*>",
        @"<link[^>]*>",
        @"<meta[^>]*>",
        @"eval\s*\(",
        @"document\.(write|cookie)",
        @"window\.(location|open)",
        @"alert\s*\(",
        @"confirm\s*\(",
        @"prompt\s*\("
    };

    private static readonly string[] StrictXSSPatterns = {
        @"<\w+[^>]*on\w+[^>]*>",
        @"<\w+[^>]*href\s*=\s*[""']javascript:",
        @"<\w+[^>]*src\s*=\s*[""']javascript:",
        @"<!--.*?-->",
        @"<!\[CDATA\[.*?\]\]>",
        @"&\w+;",
        @"&#\d+;",
        @"&#x[\da-f]+;",
        @"\\\w+",
        @"String\.fromCharCode",
        @"unescape\s*\(",
        @"decodeURI\s*\(",
        @"setTimeout\s*\(",
        @"setInterval\s*\("
    };

    private static readonly string[] DefaultAllowedTags = {
        "b", "i", "u", "strong", "em", "p", "br", "ul", "ol", "li"
    };

    public NoXSSAttribute()
    {
        ErrorMessage = "Input contains potential XSS patterns";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString();
        if (string.IsNullOrWhiteSpace(input))
            return ValidationResult.Success;

        // If basic HTML is allowed, sanitize allowed tags first
        if (AllowBasicHtml)
        {
            input = SanitizeAllowedTags(input);
        }

        var regexOptions = RegexOptions.IgnoreCase | RegexOptions.Singleline;

        // Check basic XSS patterns
        foreach (var pattern in XSSPatterns)
        {
            if (Regex.IsMatch(input, pattern, regexOptions))
            {
                return new ValidationResult($"Input contains XSS pattern: {pattern}");
            }
        }

        // Check strict patterns if enabled
        if (StrictMode)
        {
            foreach (var pattern in StrictXSSPatterns)
            {
                if (Regex.IsMatch(input, pattern, regexOptions))
                {
                    return new ValidationResult($"Input contains XSS pattern: {pattern}");
                }
            }
        }

        return ValidationResult.Success;
    }

    private string SanitizeAllowedTags(string input)
    {
        var allowedTags = AllowedTags ?? DefaultAllowedTags;
        var allowedTagsPattern = string.Join("|", allowedTags.Select(Regex.Escape));
        
        // Remove all HTML tags except allowed ones
        var pattern = $@"<(?!/?({allowedTagsPattern})\b)[^>]*>";
        return Regex.Replace(input, pattern, "", RegexOptions.IgnoreCase);
    }
}

/// <summary>
/// Validates that input does not contain command injection patterns
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class NoCommandInjectionAttribute : ValidationAttribute
{
    /// <summary>
    /// Whether to perform strict validation
    /// </summary>
    public bool StrictMode { get; set; } = true;

    private static readonly string[] CommandInjectionPatterns = {
        @"(\||&|;|`|\$\(|\$\{)",
        @"\b(cat|ls|pwd|whoami|id|uname)\b",
        @"\b(wget|curl|nc|netcat|telnet)\b",
        @"\b(ping|nslookup|dig|host)\b",
        @"\b(rm|mv|cp|chmod|chown)\b",
        @"\b(ps|kill|killall|top)\b",
        @"\b(sudo|su|passwd)\b",
        @"\b(mount|umount|fdisk)\b",
        @"\b(iptables|netstat|ss)\b",
        @"\b(crontab|at|batch)\b"
    };

    private static readonly string[] StrictCommandPatterns = {
        @"\b(cmd|command|exec|system)\b",
        @"\b(shell_exec|passthru|eval)\b",
        @"\b(python|perl|ruby|php)\b",
        @"\b(bash|sh|zsh|csh|tcsh)\b",
        @"\b(powershell|cmd\.exe)\b",
        @"\.\.[\\/]",
        @"[\\/]etc[\\/]",
        @"[\\/]proc[\\/]",
        @"[\\/]sys[\\/]",
        @"[\\/]var[\\/]log",
        @"[\\/]tmp[\\/]",
        @"\$HOME",
        @"\$PATH",
        @"%SYSTEMROOT%",
        @"%TEMP%"
    };

    public NoCommandInjectionAttribute()
    {
        ErrorMessage = "Input contains potential command injection patterns";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString();
        if (string.IsNullOrWhiteSpace(input))
            return ValidationResult.Success;

        var regexOptions = RegexOptions.IgnoreCase;

        // Check basic command injection patterns
        foreach (var pattern in CommandInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, regexOptions))
            {
                return new ValidationResult($"Input contains command injection pattern: {pattern}");
            }
        }

        // Check strict patterns if enabled
        if (StrictMode)
        {
            foreach (var pattern in StrictCommandPatterns)
            {
                if (Regex.IsMatch(input, pattern, regexOptions))
                {
                    return new ValidationResult($"Input contains command injection pattern: {pattern}");
                }
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that input does not contain path traversal patterns
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class NoPathTraversalAttribute : ValidationAttribute
{
    /// <summary>
    /// Whether to allow relative paths (default: false)
    /// </summary>
    public bool AllowRelativePaths { get; set; } = false;

    /// <summary>
    /// Allowed file extensions (if specified, only these extensions are allowed)
    /// </summary>
    public string[]? AllowedExtensions { get; set; }

    /// <summary>
    /// Blocked file extensions
    /// </summary>
    public string[]? BlockedExtensions { get; set; }

    private static readonly string[] PathTraversalPatterns = {
        @"\.\.[\\/]",
        @"[\\/]\.\.[\\/]",
        @"\.\.%2[fF]",
        @"%2[eE]%2[eE]%2[fF]",
        @"\.\.\\",
        @"\.\./",
        @"%c0%af",
        @"%c1%9c"
    };

    private static readonly string[] DangerousExtensions = {
        ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js", ".jar",
        ".php", ".asp", ".aspx", ".jsp", ".py", ".pl", ".rb", ".sh", ".ps1"
    };

    public NoPathTraversalAttribute()
    {
        ErrorMessage = "Input contains potential path traversal patterns";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString();
        if (string.IsNullOrWhiteSpace(input))
            return ValidationResult.Success;

        // Check for path traversal patterns
        foreach (var pattern in PathTraversalPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                return new ValidationResult($"Input contains path traversal pattern: {pattern}");
            }
        }

        // Check relative paths if not allowed
        if (!AllowRelativePaths && (input.Contains("..") || input.StartsWith("./") || input.StartsWith(".\\")))
        {
            return new ValidationResult("Relative paths are not allowed");
        }

        // Check file extensions
        var extension = Path.GetExtension(input)?.ToLowerInvariant();
        if (!string.IsNullOrEmpty(extension))
        {
            // Check blocked extensions
            if (BlockedExtensions?.Contains(extension) == true)
            {
                return new ValidationResult($"File extension '{extension}' is not allowed");
            }

            // Check dangerous extensions
            if (DangerousExtensions.Contains(extension))
            {
                return new ValidationResult($"Potentially dangerous file extension '{extension}' is not allowed");
            }

            // Check allowed extensions (if specified)
            if (AllowedExtensions?.Length > 0 && !AllowedExtensions.Contains(extension))
            {
                return new ValidationResult($"File extension '{extension}' is not in the allowed list");
            }
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that input contains only safe characters for security contexts
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class SafeCharactersAttribute : ValidationAttribute
{
    /// <summary>
    /// Character set to allow (predefined sets or custom pattern)
    /// </summary>
    public SafeCharacterSet CharacterSet { get; set; } = SafeCharacterSet.Alphanumeric;

    /// <summary>
    /// Custom regex pattern for allowed characters
    /// </summary>
    public string? CustomPattern { get; set; }

    /// <summary>
    /// Additional characters to allow beyond the base character set
    /// </summary>
    public string? AdditionalCharacters { get; set; }

    /// <summary>
    /// Whether to allow whitespace characters
    /// </summary>
    public bool AllowWhitespace { get; set; } = false;

    /// <summary>
    /// Whether to allow Unicode characters
    /// </summary>
    public bool AllowUnicode { get; set; } = false;

    public SafeCharactersAttribute()
    {
        ErrorMessage = "Input contains unsafe characters";
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
            return ValidationResult.Success;

        var input = value.ToString();
        if (string.IsNullOrWhiteSpace(input))
            return ValidationResult.Success;

        string pattern;

        if (!string.IsNullOrEmpty(CustomPattern))
        {
            pattern = CustomPattern;
        }
        else
        {
            pattern = CharacterSet switch
            {
                SafeCharacterSet.Alphanumeric => @"[a-zA-Z0-9]",
                SafeCharacterSet.AlphanumericWithHyphen => @"[a-zA-Z0-9\-]",
                SafeCharacterSet.AlphanumericWithUnderscore => @"[a-zA-Z0-9_]",
                SafeCharacterSet.AlphanumericWithHyphenUnderscore => @"[a-zA-Z0-9\-_]",
                SafeCharacterSet.Numeric => @"[0-9]",
                SafeCharacterSet.Alpha => @"[a-zA-Z]",
                SafeCharacterSet.Hexadecimal => @"[a-fA-F0-9]",
                SafeCharacterSet.Base64 => @"[a-zA-Z0-9+/=]",
                SafeCharacterSet.EmailSafe => @"[a-zA-Z0-9@.\-_]",
                SafeCharacterSet.UrlSafe => @"[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]",
                _ => @"[a-zA-Z0-9]"
            };
        }

        // Add additional characters if specified
        if (!string.IsNullOrEmpty(AdditionalCharacters))
        {
            var escapedChars = Regex.Escape(AdditionalCharacters);
            pattern = pattern.TrimEnd(']') + escapedChars + "]";
        }

        // Add whitespace if allowed
        if (AllowWhitespace)
        {
            pattern = pattern.TrimEnd(']') + @"\s]";
        }

        // Create full pattern to match entire string
        var fullPattern = $"^{pattern}+$";

        var regexOptions = RegexOptions.None;
        if (AllowUnicode)
        {
            regexOptions |= RegexOptions.IgnoreCase;
        }

        if (!Regex.IsMatch(input, fullPattern, regexOptions))
        {
            return new ValidationResult($"Input contains characters not allowed by the {CharacterSet} character set");
        }

        return ValidationResult.Success;
    }
}

/// <summary>
/// Safe character sets for validation
/// </summary>
public enum SafeCharacterSet
{
    /// <summary>
    /// Letters and numbers only (a-z, A-Z, 0-9)
    /// </summary>
    Alphanumeric,

    /// <summary>
    /// Letters, numbers, and hyphens (a-z, A-Z, 0-9, -)
    /// </summary>
    AlphanumericWithHyphen,

    /// <summary>
    /// Letters, numbers, and underscores (a-z, A-Z, 0-9, _)
    /// </summary>
    AlphanumericWithUnderscore,

    /// <summary>
    /// Letters, numbers, hyphens, and underscores (a-z, A-Z, 0-9, -, _)
    /// </summary>
    AlphanumericWithHyphenUnderscore,

    /// <summary>
    /// Numbers only (0-9)
    /// </summary>
    Numeric,

    /// <summary>
    /// Letters only (a-z, A-Z)
    /// </summary>
    Alpha,

    /// <summary>
    /// Hexadecimal characters (a-f, A-F, 0-9)
    /// </summary>
    Hexadecimal,

    /// <summary>
    /// Base64 characters (a-z, A-Z, 0-9, +, /, =)
    /// </summary>
    Base64,

    /// <summary>
    /// Email-safe characters (a-z, A-Z, 0-9, @, ., -, _)
    /// </summary>
    EmailSafe,

    /// <summary>
    /// URL-safe characters
    /// </summary>
    UrlSafe
}