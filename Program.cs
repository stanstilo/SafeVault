using System;
using System.Threading.Tasks;

namespace SafeVault;

public static class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("SafeVault secure code sample starting...");

        const string connectionString = "Data Source=SafeVault.db";
        var dataAccess = new DataAccess(connectionString);
        await dataAccess.InitializeAsync();

        var username = "attacker'; DROP TABLE Users; --";
        var email = "test@example.com";
        var sanitizedUsername = InputSanitizer.SanitizeForDisplay(username);
        Console.WriteLine($"Sanitized username for display: {sanitizedUsername}");

        await dataAccess.AddUserAsync(username, email);
        var count = await dataAccess.CountUsersAsync();
        Console.WriteLine($"User count after insertion: {count}");

        Console.WriteLine("SafeVault run completed successfully.");
    }
}
