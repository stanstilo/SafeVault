using NUnit.Framework;
using System;
using System.IO;
using System.Threading.Tasks;
using SafeVault;

[TestFixture]
public class TestAuthentication
{
    private string _dbFile = null!;
    private string ConnectionString => $"Data Source={_dbFile}";
    private DataAccess _dataAccess = null!;
    private AuthenticationService _authService = null!;

    [SetUp]
    public async Task Setup()
    {
        _dbFile = Path.Combine(Path.GetTempPath(), $"SafeVaultAuth_{Guid.NewGuid()}.db");
        _dataAccess = new DataAccess(ConnectionString);
        await _dataAccess.InitializeAsync();
        _authService = new AuthenticationService(_dataAccess);
    }

    [TearDown]
    public void TearDown()
    {
        if (File.Exists(_dbFile)) File.Delete(_dbFile);
    }

    [Test]
    public async Task TestPasswordHashing()
    {
        var password = "SecurePassword123!";
        var hash1 = _authService.HashPassword(password);
        var hash2 = _authService.HashPassword(password);

        Assert.AreNotEqual(hash1, hash2, "Hashes should be different (salted).");
        Assert.IsTrue(_authService.VerifyPassword(password, hash1), "Password should verify against hash1.");
        Assert.IsTrue(_authService.VerifyPassword(password, hash2), "Password should verify against hash2.");
    }

    [Test]
    public async Task TestPasswordVerification()
    {
        var password = "MyPassword123";
        var hash = _authService.HashPassword(password);

        Assert.IsTrue(_authService.VerifyPassword(password, hash), "Correct password should verify.");
        Assert.IsFalse(_authService.VerifyPassword("WrongPassword", hash), "Incorrect password should not verify.");
    }

    [Test]
    public async Task TestUserRegistration()
    {
        var success = await _authService.RegisterUserAsync("alice", "alice@example.com", "password123");
        Assert.IsTrue(success, "Registration should succeed.");

        var (username, hash, role) = await _dataAccess.GetUserByUsernameAsync("alice");
        Assert.AreEqual("alice", username);
        Assert.IsNotNull(hash);
        Assert.AreEqual("User", role);
    }

    [Test]
    public async Task TestDuplicateUserRegistration()
    {
        await _authService.RegisterUserAsync("bob", "bob@example.com", "pass123");
        var success = await _authService.RegisterUserAsync("bob", "bob2@example.com", "pass456");
        Assert.IsFalse(success, "Duplicate registration should fail.");
    }

    [Test]
    public async Task TestLogin()
    {
        await _authService.RegisterUserAsync("charlie", "charlie@example.com", "password456");
        var (success, role) = await _authService.LoginAsync("charlie", "password456");

        Assert.IsTrue(success, "Login should succeed with correct credentials.");
        Assert.AreEqual("User", role);
    }

    [Test]
    public async Task TestInvalidLogin()
    {
        await _authService.RegisterUserAsync("dave", "dave@example.com", "correctpass");
        
        var (success1, _) = await _authService.LoginAsync("dave", "wrongpass");
        Assert.IsFalse(success1, "Login should fail with wrong password.");

        var (success2, _) = await _authService.LoginAsync("nonexistent", "anypass");
        Assert.IsFalse(success2, "Login should fail for non-existent user.");
    }

    [Test]
    public async Task TestEmptyCredentials()
    {
        var (success1, _) = await _authService.LoginAsync("", "password");
        Assert.IsFalse(success1, "Login should fail with empty username.");

        var (success2, _) = await _authService.LoginAsync("user", "");
        Assert.IsFalse(success2, "Login should fail with empty password.");
    }
}
