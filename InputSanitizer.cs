using System.Text.RegularExpressions;
using System.Net.Mail;

namespace SafeVault;

public static class InputSanitizer
{
    // For user input in web contexts, remove HTML/script tags to prevent XSS
    public static string SanitizeForDisplay(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;

        // Remove script blocks
        input = Regex.Replace(input, "<script.*?>.*?</script>", string.Empty, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        // Remove any other HTML tags
        input = Regex.Replace(input, "<.*?>", string.Empty, RegexOptions.Singleline);
        // Collapse multiple whitespace
        input = Regex.Replace(input, "\\s+", " ").Trim();
        return input;
    }

    // For database inputs, trust parameterized queries for SQL injection protection
    public static string Sanitize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        // Only trim and collapse whitespace; rely on parameterized queries for SQL safety
        input = Regex.Replace(input, "\\s+", " ").Trim();
        return input;
    }

    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        try
        {
            var addr = new MailAddress(email);
            return !string.IsNullOrWhiteSpace(addr.Address);
        }
        catch
        {
            return false;
        }
    }
}