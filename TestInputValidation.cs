using NUnit.Framework;
using System;
using System.IO;
using System.Threading.Tasks;
using SafeVault;

[TestFixture]
public class TestInputValidation
{
    private string _dbFile = null!;
    private string ConnectionString => $"Data Source={_dbFile}";

    [SetUp]
    public void Setup()
    {
        _dbFile = Path.Combine(Path.GetTempPath(), $"SafeVaultTest_{Guid.NewGuid()}.db");
    }

    [TearDown]
    public void TearDown()
    {
        if (File.Exists(_dbFile)) File.Delete(_dbFile);
    }

    [Test]
    public async Task TestForSQLInjection()
    {
        var db = new DataAccess(ConnectionString);
        await db.InitializeAsync();

        var malicious = "'; DROP TABLE Users; --";
        // Add a user with malicious payload in username
        Assert.DoesNotThrowAsync(async () => await db.AddUserAsync(malicious, "attacker@example.com"));

        // Ensure we can still add another legitimate user (table wasn't dropped)
        await db.AddUserAsync("legituser", "legit@example.com");
        var count = await db.CountUsersAsync();
        Assert.AreEqual(2, count, "Table should still exist and contain both records.");

        // Verify parameterized queries prevented SQL injection - table still exists
        Assert.Pass("SQL injection prevented by parameterized queries - table was not dropped.");
    }

    [Test]
    public void TestForXSS()
    {
        var input = "<script>alert(1)</script><b>Alice</b>";
        var cleaned = InputSanitizer.SanitizeForDisplay(input);
        Assert.IsFalse(cleaned.Contains("<script"), "Script tags should be removed");
        Assert.IsFalse(cleaned.Contains("<"), "No HTML tags should remain");
        Assert.AreEqual("Alice", cleaned);
    }
}
