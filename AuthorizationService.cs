namespace SafeVault;

public class AuthorizationService
{
    private readonly DataAccess _dataAccess;

    public AuthorizationService(DataAccess dataAccess)
    {
        _dataAccess = dataAccess;
    }

    public async Task<bool> HasRoleAsync(string username, string requiredRole)
    {
        var (_, _, role) = await _dataAccess.GetUserByUsernameAsync(username);
        return role?.Equals(requiredRole, StringComparison.OrdinalIgnoreCase) ?? false;
    }

    public async Task<bool> CanAccessAdminAsync(string username)
    {
        return await HasRoleAsync(username, "Admin");
    }

    public async Task<bool> CanAccessUserPanelAsync(string username)
    {
        var (_, _, role) = await _dataAccess.GetUserByUsernameAsync(username);
        return role != null && (role.Equals("Admin", StringComparison.OrdinalIgnoreCase) || role.Equals("User", StringComparison.OrdinalIgnoreCase));
    }
}