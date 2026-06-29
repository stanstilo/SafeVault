using BCrypt.Net;

namespace SafeVault;

public class AuthenticationService
{
    private readonly DataAccess _dataAccess;

    public AuthenticationService(DataAccess dataAccess)
    {
        _dataAccess = dataAccess;
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }

    public bool VerifyPassword(string password, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> RegisterUserAsync(string username, string email, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        var existingUser = await _dataAccess.GetUserByUsernameAsync(username);
        if (existingUser.username != null)
        {
            return false;
        }

        var hash = HashPassword(password);
        await _dataAccess.AddUserAsync(username, email);
        await _dataAccess.SetPasswordAsync(username, hash);
        return true;
    }

    public async Task<(bool success, string? role)> LoginAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return (false, null);
        }

        var (storedUsername, passwordHash, role) = await _dataAccess.GetUserByUsernameAsync(username);
        if (storedUsername == null || passwordHash == null)
        {
            return (false, null);
        }

        if (!VerifyPassword(password, passwordHash))
        {
            return (false, null);
        }

        return (true, role);
    }
}