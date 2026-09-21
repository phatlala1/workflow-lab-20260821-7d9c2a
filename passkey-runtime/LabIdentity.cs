using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

internal sealed class LabUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? UserName { get; set; }
    public string? NormalizedUserName { get; set; }
    public string Role { get; set; } = "user";
    public List<UserPasskeyInfo> Passkeys { get; } = [];
}

internal sealed class LabUserStore : IUserStore<LabUser>, IUserPasskeyStore<LabUser>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, LabUser> _usersById = new(StringComparer.Ordinal);

    public LabUser Admin { get; }
    public LabUser LowUser { get; }

    public LabUserStore()
    {
        Admin = new LabUser
        {
            Id = "owned-admin-0001",
            UserName = "admin@example.test",
            NormalizedUserName = "ADMIN@EXAMPLE.TEST",
            Role = "admin",
        };
        LowUser = new LabUser
        {
            Id = "owned-low-0001",
            UserName = "low@example.test",
            NormalizedUserName = "LOW@EXAMPLE.TEST",
            Role = "user",
        };
        _usersById[Admin.Id] = Admin;
        _usersById[LowUser.Id] = LowUser;
    }

    public int GetPasskeyCount(string userId)
    {
        lock (_gate)
        {
            return _usersById.TryGetValue(userId, out var user) ? user.Passkeys.Count : 0;
        }
    }

    public string? GetPasskeyOwnerId(byte[] credentialId)
    {
        lock (_gate)
        {
            return _usersById.Values
                .FirstOrDefault(user => user.Passkeys.Any(passkey => passkey.CredentialId.AsSpan().SequenceEqual(credentialId)))
                ?.Id;
        }
    }

    public Task<IdentityResult> CreateAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        lock (_gate)
        {
            if (_usersById.ContainsKey(user.Id))
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "DuplicateId",
                    Description = "A user with the same synthetic ID already exists.",
                }));
            }
            user.NormalizedUserName ??= user.UserName?.ToUpperInvariant();
            _usersById[user.Id] = user;
        }
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> UpdateAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        lock (_gate)
        {
            _usersById[user.Id] = user;
        }
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        lock (_gate)
        {
            _usersById.Remove(user.Id);
        }
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<string> GetUserIdAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.Id);
    }

    public Task<string?> GetUserNameAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.UserName);
    }

    public Task SetUserNameAsync(LabUser user, string? userName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        user.UserName = userName;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedUserNameAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.NormalizedUserName);
    }

    public Task SetNormalizedUserNameAsync(LabUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task<LabUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            return Task.FromResult(_usersById.TryGetValue(userId, out var user) ? user : null);
        }
    }

    public Task<LabUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            return Task.FromResult(_usersById.Values.FirstOrDefault(user =>
                string.Equals(user.NormalizedUserName, normalizedUserName, StringComparison.Ordinal)));
        }
    }

    public Task AddOrUpdatePasskeyAsync(LabUser user, UserPasskeyInfo passkey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(passkey);
        lock (_gate)
        {
            var index = user.Passkeys.FindIndex(existing =>
                existing.CredentialId.AsSpan().SequenceEqual(passkey.CredentialId));
            if (index < 0)
            {
                user.Passkeys.Add(passkey);
            }
            else
            {
                user.Passkeys[index] = passkey;
            }
        }
        return Task.CompletedTask;
    }

    public Task<IList<UserPasskeyInfo>> GetPasskeysAsync(LabUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        lock (_gate)
        {
            return Task.FromResult<IList<UserPasskeyInfo>>(user.Passkeys.ToList());
        }
    }

    public Task<LabUser?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(credentialId);
        lock (_gate)
        {
            return Task.FromResult(_usersById.Values.FirstOrDefault(user =>
                user.Passkeys.Any(passkey => passkey.CredentialId.AsSpan().SequenceEqual(credentialId))));
        }
    }

    public Task<UserPasskeyInfo?> FindPasskeyAsync(LabUser user, byte[] credentialId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(credentialId);
        lock (_gate)
        {
            return Task.FromResult(user.Passkeys.FirstOrDefault(passkey =>
                passkey.CredentialId.AsSpan().SequenceEqual(credentialId)));
        }
    }

    public Task RemovePasskeyAsync(LabUser user, byte[] credentialId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(credentialId);
        lock (_gate)
        {
            user.Passkeys.RemoveAll(passkey => passkey.CredentialId.AsSpan().SequenceEqual(credentialId));
        }
        return Task.CompletedTask;
    }

    public void Dispose()
    {
    }
}

internal sealed class LabClaimsPrincipalFactory : IUserClaimsPrincipalFactory<LabUser>
{
    public Task<ClaimsPrincipal> CreateAsync(LabUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        var identity = new ClaimsIdentity(
            IdentityConstants.ApplicationScheme,
            ClaimTypes.Name,
            ClaimTypes.Role);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName ?? user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Role, user.Role));
        identity.AddClaim(new Claim("owned_lab_user", "true"));
        return Task.FromResult(new ClaimsPrincipal(identity));
    }
}
