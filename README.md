# SafeVault (Secure Coding Exercise)

This folder contains a small library that demonstrates input sanitization and parameterized database access to mitigate SQL injection and XSS.

- `InputSanitizer.cs` — sanitizes inputs and validates email.
- `DataAccess.cs` — uses `Microsoft.Data.Sqlite` with parameterized statements.
- `wwwroot/webform.html` — example web form.

Build:

```bash
cd SafeVault
dotnet build
```

Run tests (created in `SafeVault.Tests`):

```bash
cd ..
dotnet test
```
