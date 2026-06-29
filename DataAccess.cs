using System;
using Microsoft.Data.Sqlite;

namespace SafeVault;

public class DataAccess
{
    private readonly string _connectionString;

    public DataAccess(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task InitializeAsync()
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT UNIQUE NOT NULL,
            Email TEXT NOT NULL,
            PasswordHash TEXT NOT NULL,
            Role TEXT NOT NULL DEFAULT 'User'
        );";
        await cmd.ExecuteNonQueryAsync();

        await EnsureColumnExistsAsync(conn, "Users", "PasswordHash", "TEXT NOT NULL DEFAULT ''");
        await EnsureColumnExistsAsync(conn, "Users", "Role", "TEXT NOT NULL DEFAULT 'User'");
    }

    private static async Task EnsureColumnExistsAsync(SqliteConnection conn, string tableName, string columnName, string columnDefinition)
    {
        var checkCmd = conn.CreateCommand();
        checkCmd.CommandText = $"PRAGMA table_info({tableName});";
        await using var reader = await checkCmd.ExecuteReaderAsync();
        var found = false;
        while (await reader.ReadAsync())
        {
            if (reader.GetString(1).Equals(columnName, StringComparison.OrdinalIgnoreCase))
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            var alterCmd = conn.CreateCommand();
            alterCmd.CommandText = $"ALTER TABLE {tableName} ADD COLUMN {columnName} {columnDefinition};";
            await alterCmd.ExecuteNonQueryAsync();
        }
    }

    public async Task AddUserAsync(string username, string email)
    {
        var sanitizedUsername = InputSanitizer.Sanitize(username);
        var sanitizedEmail = InputSanitizer.Sanitize(email);

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @hash, @role);";
        cmd.Parameters.AddWithValue("@username", sanitizedUsername);
        cmd.Parameters.AddWithValue("@email", sanitizedEmail);
        cmd.Parameters.AddWithValue("@hash", "");
        cmd.Parameters.AddWithValue("@role", "User");
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<(string? username, string? passwordHash, string? role)> GetUserByUsernameAsync(string username)
    {
        var sanitized = InputSanitizer.Sanitize(username);
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Username, PasswordHash, Role FROM Users WHERE Username = @username LIMIT 1;";
        cmd.Parameters.AddWithValue("@username", sanitized);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return (reader.GetString(0), reader.GetString(1), reader.GetString(2));
        }
        return (null, null, null);
    }

    public async Task SetPasswordAsync(string username, string passwordHash)
    {
        var sanitized = InputSanitizer.Sanitize(username);
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE Users SET PasswordHash = @hash WHERE Username = @username;";
        cmd.Parameters.AddWithValue("@hash", passwordHash);
        cmd.Parameters.AddWithValue("@username", sanitized);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task SetRoleAsync(string username, string role)
    {
        var sanitized = InputSanitizer.Sanitize(username);
        var sanitizedRole = InputSanitizer.Sanitize(role);
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE Users SET Role = @role WHERE Username = @username;";
        cmd.Parameters.AddWithValue("@role", sanitizedRole);
        cmd.Parameters.AddWithValue("@username", sanitized);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<int> CountUsersAsync()
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(1) FROM Users;";
        var result = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(result ?? 0);
    }
}