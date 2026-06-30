using NUnit.Framework;
using System;
using System.IO;
using System.Threading.Tasks;
using SafeVault;

[TestFixture]
public class TestAuthorization
{
    private string _dbFile = null!;
    private string ConnectionString => $"Data Source={_dbFile}";
    private DataAccess _dataAccess = null!;
    private AuthenticationService _authService = null!;
    private AuthorizationService _authzService = null!;

    [SetUp]
    public async Task Setup()
    {
        _dbFile = Path.Combine(Path.GetTempPath(), $"SafeVaultAuthz_{Guid.NewGuid()}.db");
        _dataAccess = new DataAccess(ConnectionString);
        await _dataAccess.InitializeAsync();
        _authService = new AuthenticationService(_dataAccess);
        _authzService = new AuthorizationService(_dataAccess);
    }

    [TearDown]
    public void TearDown()
    {
        if (File.Exists(_dbFile)) File.Delete(_dbFile);
    }

    [Test]
    public async Task TestUserRoleAssignment()
    {
        await _authService.RegisterUserAsync("eve", "eve@example.com", "password");
        await _dataAccess.SetRoleAsync("eve", "Admin");

        var hasAdminRole = await _authzService.HasRoleAsync("eve", "Admin");
        Assert.IsTrue(hasAdminRole, "User should have Admin role.");

        var hasUserRole = await _authzService.HasRoleAsync("eve", "User");
        Assert.IsFalse(hasUserRole, "User should not have User role.");
    }

    [Test]
    public async Task TestAdminAccess()
    {
        await _authService.RegisterUserAsync("frank", "frank@example.com", "password");
        await _dataAccess.SetRoleAsync("frank", "Admin");

        var canAccess = await _authzService.CanAccessAdminAsync("frank");
        Assert.IsTrue(canAccess, "Admin should access admin panel.");
    }

    [Test]
    public async Task TestUserCannotAccessAdmin()
    {
        await _authService.RegisterUserAsync("grace", "grace@example.com", "password");
        // Default role is 'User'

        var canAccess = await _authzService.CanAccessAdminAsync("grace");
        Assert.IsFalse(canAccess, "Regular user should not access admin panel.");
    }

    [Test]
    public async Task TestUserPanelAccess()
    {
        await _authService.RegisterUserAsync("henry", "henry@example.com", "password");
        var canAccess = await _authzService.CanAccessUserPanelAsync("henry");
        Assert.IsTrue(canAccess, "User should access user panel.");

        await _dataAccess.SetRoleAsync("henry", "Admin");
        var adminCanAccess = await _authzService.CanAccessUserPanelAsync("henry");
        Assert.IsTrue(adminCanAccess, "Admin should also access user panel.");
    }

    [Test]
    public async Task TestNonExistentUserAccess()
    {
        var canAccessAdmin = await _authzService.CanAccessAdminAsync("nonexistent");
        Assert.IsFalse(canAccessAdmin, "Non-existent user should not access admin.");

        var canAccessUser = await _authzService.CanAccessUserPanelAsync("nonexistent");
        Assert.IsFalse(canAccessUser, "Non-existent user should not access user panel.");
    }

    [Test]
    public async Task TestRoleBasedAccessControl()
    {
        // Create regular user
        await _authService.RegisterUserAsync("iris", "iris@example.com", "password");

        // Create admin user
        await _authService.RegisterUserAsync("jack", "jack@example.com", "password");
        await _dataAccess.SetRoleAsync("jack", "Admin");

        // Test access
        Assert.IsFalse(await _authzService.CanAccessAdminAsync("iris"), "Regular user denied.");
        Assert.IsTrue(await _authzService.CanAccessAdminAsync("jack"), "Admin granted.");
        Assert.IsTrue(await _authzService.CanAccessUserPanelAsync("iris"), "User can access user panel.");
        Assert.IsTrue(await _authzService.CanAccessUserPanelAsync("jack"), "Admin can access user panel.");
    }
}
