using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

internal sealed class SyntheticPasskey : IDisposable
{
    private readonly ECDsa _key;
    private readonly byte[] _credentialId;
    private readonly byte[] _publicKeyCose;

    private SyntheticPasskey(ECDsa key, byte[] credentialId, byte[] publicKeyCose)
    {
        _key = key;
        _credentialId = credentialId;
        _publicKeyCose = publicKeyCose;
    }

    public byte[] CredentialId => _credentialId.ToArray();

    public static SyntheticPasskey CreateEs256()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(includePrivateParameters: false);
        return new SyntheticPasskey(
            key,
            RandomNumberGenerator.GetBytes(32),
            EncodeEs256PublicKey(parameters));
    }

    public AttestationMaterial CreateAttestation(
        string creationOptionsJson,
        string origin,
        string expectedUserId,
        string? challengeOverride = null,
        string? originOverride = null)
    {
        using var optionsDocument = JsonDocument.Parse(creationOptionsJson);
        var root = optionsDocument.RootElement;
        var challenge = root.GetProperty("challenge").GetString()
            ?? throw new InvalidOperationException("Creation options omitted challenge.");
        var rpId = root.GetProperty("rp").GetProperty("id").GetString()
            ?? throw new InvalidOperationException("Creation options omitted rp.id.");
        var encodedUserId = root.GetProperty("user").GetProperty("id").GetString()
            ?? throw new InvalidOperationException("Creation options omitted user.id.");
        var userIdBytes = Base64UrlDecode(encodedUserId);
        var userEntityMatchesExpected = userIdBytes.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(expectedUserId));

        var attestedCredentialData = BuildAttestedCredentialData(_credentialId, _publicKeyCose);
        var authenticatorData = BuildAttestationAuthenticatorData(rpId, attestedCredentialData, signCount: 1);
        var attestationObject = BuildNoneAttestationObject(authenticatorData);
        var effectiveChallenge = challengeOverride ?? challenge;
        var effectiveOrigin = originOverride ?? origin;
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
        {
            challenge = effectiveChallenge,
            origin = effectiveOrigin,
            type = "webauthn.create",
        });
        var credentialJson = JsonSerializer.Serialize(new
        {
            id = Base64UrlEncode(_credentialId),
            response = new
            {
                attestationObject = Base64UrlEncode(attestationObject),
                clientDataJSON = Base64UrlEncode(clientDataJson),
                transports = new[] { "internal" },
            },
            type = "public-key",
            clientExtensionResults = new { },
            authenticatorAttachment = "platform",
        });

        return new AttestationMaterial(
            Challenge: challenge,
            EffectiveChallenge: effectiveChallenge,
            RpId: rpId,
            Origin: effectiveOrigin,
            ExpectedUserId: expectedUserId,
            UserEntityMatchesExpected: userEntityMatchesExpected,
            CredentialJson: credentialJson,
            CredentialId: _credentialId.ToArray(),
            AuthenticatorData: authenticatorData,
            AttestationObject: attestationObject,
            ClientDataJson: clientDataJson);
    }

    public AssertionMaterial CreateAssertion(
        string requestOptionsJson,
        string origin,
        string userId,
        uint signCount = 2,
        ECDsa? signingKeyOverride = null)
    {
        using var optionsDocument = JsonDocument.Parse(requestOptionsJson);
        var root = optionsDocument.RootElement;
        var challenge = root.GetProperty("challenge").GetString()
            ?? throw new InvalidOperationException("Request options omitted challenge.");
        var rpId = root.GetProperty("rpId").GetString()
            ?? throw new InvalidOperationException("Request options omitted rpId.");

        var authenticatorData = new byte[37];
        SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authenticatorData, 0);
        authenticatorData[32] = 0x05;
        BinaryPrimitives.WriteUInt32BigEndian(authenticatorData.AsSpan(33, 4), signCount);

        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new
        {
            challenge,
            origin,
            type = "webauthn.get",
        });
        var clientDataHash = SHA256.HashData(clientDataJson);
        var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signedData, 0);
        clientDataHash.CopyTo(signedData, authenticatorData.Length);
        var signingKey = signingKeyOverride ?? _key;
        var signature = signingKey.SignData(
            signedData,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        var credentialJson = BuildAssertionCredentialJson(
            _credentialId,
            authenticatorData,
            clientDataJson,
            signature,
            Encoding.UTF8.GetBytes(userId));

        return new AssertionMaterial(
            Challenge: challenge,
            RpId: rpId,
            Origin: origin,
            SignCount: signCount,
            CredentialJson: credentialJson,
            AuthenticatorData: authenticatorData,
            ClientDataJson: clientDataJson,
            Signature: signature,
            CredentialId: _credentialId.ToArray(),
            UserHandle: Encoding.UTF8.GetBytes(userId));
    }

    public static string FlipAssertionSignatureBit(string credentialJson)
    {
        var root = JsonNode.Parse(credentialJson)?.AsObject()
            ?? throw new InvalidOperationException("Credential JSON was not an object.");
        var signatureValue = root["response"]?["signature"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Assertion credential omitted response.signature.");
        var signature = Base64UrlDecode(signatureValue);
        signature[^1] ^= 0x01;
        root["response"]!["signature"] = Base64UrlEncode(signature);
        return root.ToJsonString();
    }

    private static string BuildAssertionCredentialJson(
        byte[] credentialId,
        byte[] authenticatorData,
        byte[] clientDataJson,
        byte[] signature,
        byte[] userHandle)
        => JsonSerializer.Serialize(new
        {
            id = Base64UrlEncode(credentialId),
            response = new
            {
                authenticatorData = Base64UrlEncode(authenticatorData),
                clientDataJSON = Base64UrlEncode(clientDataJson),
                signature = Base64UrlEncode(signature),
                userHandle = Base64UrlEncode(userHandle),
            },
            type = "public-key",
            clientExtensionResults = new { },
            authenticatorAttachment = "platform",
        });

    private static byte[] BuildAttestedCredentialData(byte[] credentialId, byte[] publicKeyCose)
    {
        var result = new byte[16 + 2 + credentialId.Length + publicKeyCose.Length];
        var offset = 16;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset, 2), checked((ushort)credentialId.Length));
        offset += 2;
        credentialId.CopyTo(result, offset);
        offset += credentialId.Length;
        publicKeyCose.CopyTo(result, offset);
        return result;
    }

    private static byte[] BuildAttestationAuthenticatorData(
        string rpId,
        byte[] attestedCredentialData,
        uint signCount)
    {
        var result = new byte[37 + attestedCredentialData.Length];
        SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(result, 0);
        result[32] = 0x45;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(33, 4), signCount);
        attestedCredentialData.CopyTo(result, 37);
        return result;
    }

    private static byte[] BuildNoneAttestationObject(byte[] authenticatorData)
    {
        using var stream = new MemoryStream();
        WriteMapHeader(stream, 3);
        WriteTextString(stream, "fmt");
        WriteTextString(stream, "none");
        WriteTextString(stream, "attStmt");
        WriteMapHeader(stream, 0);
        WriteTextString(stream, "authData");
        WriteByteString(stream, authenticatorData);
        return stream.ToArray();
    }

    private static byte[] EncodeEs256PublicKey(ECParameters parameters)
    {
        var x = parameters.Q.X ?? throw new InvalidOperationException("EC public key has no X coordinate.");
        var y = parameters.Q.Y ?? throw new InvalidOperationException("EC public key has no Y coordinate.");
        if (x.Length != 32 || y.Length != 32)
        {
            throw new InvalidOperationException("Expected P-256 coordinates to be 32 bytes.");
        }

        var result = new byte[77];
        var offset = 0;
        result[offset++] = 0xA5;
        result[offset++] = 0x01;
        result[offset++] = 0x02;
        result[offset++] = 0x03;
        result[offset++] = 0x26;
        result[offset++] = 0x20;
        result[offset++] = 0x01;
        result[offset++] = 0x21;
        result[offset++] = 0x58;
        result[offset++] = 0x20;
        x.CopyTo(result, offset);
        offset += x.Length;
        result[offset++] = 0x22;
        result[offset++] = 0x58;
        result[offset++] = 0x20;
        y.CopyTo(result, offset);
        offset += y.Length;
        if (offset != result.Length)
        {
            throw new InvalidOperationException("COSE key length mismatch.");
        }
        return result;
    }

    private static void WriteMapHeader(Stream stream, int count)
        => WriteMajorTypeLength(stream, majorType: 5, checked((ulong)count));

    private static void WriteTextString(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteMajorTypeLength(stream, majorType: 3, checked((ulong)bytes.Length));
        stream.Write(bytes);
    }

    private static void WriteByteString(Stream stream, byte[] value)
    {
        WriteMajorTypeLength(stream, majorType: 2, checked((ulong)value.Length));
        stream.Write(value);
    }

    private static void WriteMajorTypeLength(Stream stream, int majorType, ulong length)
    {
        var prefix = checked((byte)(majorType << 5));
        if (length < 24)
        {
            stream.WriteByte((byte)(prefix | (byte)length));
        }
        else if (length <= byte.MaxValue)
        {
            stream.WriteByte((byte)(prefix | 24));
            stream.WriteByte((byte)length);
        }
        else if (length <= ushort.MaxValue)
        {
            stream.WriteByte((byte)(prefix | 25));
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)length);
            stream.Write(buffer);
        }
        else
        {
            throw new NotSupportedException("Synthetic CBOR writer supports values up to UInt16 length.");
        }
    }

    public static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += padded.Length % 4 switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new FormatException("Invalid base64url length."),
        };
        return Convert.FromBase64String(padded);
    }

    public void Dispose() => _key.Dispose();
}

internal sealed record AttestationMaterial(
    string Challenge,
    string EffectiveChallenge,
    string RpId,
    string Origin,
    string ExpectedUserId,
    bool UserEntityMatchesExpected,
    string CredentialJson,
    byte[] CredentialId,
    byte[] AuthenticatorData,
    byte[] AttestationObject,
    byte[] ClientDataJson);

internal sealed record AssertionMaterial(
    string Challenge,
    string RpId,
    string Origin,
    uint SignCount,
    string CredentialJson,
    byte[] AuthenticatorData,
    byte[] ClientDataJson,
    byte[] Signature,
    byte[] CredentialId,
    byte[] UserHandle);
