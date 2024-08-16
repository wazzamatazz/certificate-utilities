// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NET8_0_OR_GREATER
using System.Security.Cryptography;
#endif
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

namespace Jaahas.CertificateUtilities {

    /// <summary>
    /// Helper class for loading certificates from the file system or from a certificate store.
    /// </summary>
    public sealed partial class CertificateLoader {

        /// <summary>
        /// OID for server authentication.
        /// </summary>
        public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

        /// <summary>
        /// OID for client authentication.
        /// </summary>
        public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        /// The certificate loader options.
        /// </summary>
        private readonly CertificateLoaderOptions _options;

        /// <summary>
        /// Logging.
        /// </summary>
        private readonly ILogger<CertificateLoader> _logger;


        /// <summary>
        /// Creates a new <see cref="CertificateLoader"/> instance.
        /// </summary>
        /// <param name="options">
        ///   The certificate loader options.
        /// </param>
        /// <param name="logger">
        ///   The logger.
        /// </param>
        public CertificateLoader(CertificateLoaderOptions? options = null, ILogger<CertificateLoader>? logger = null) {
            _options = options ?? new CertificateLoaderOptions();
            _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<CertificateLoader>.Instance;
        }


        /// <summary>
        /// Loads a certificate using the specified configuration.
        /// </summary>
        /// <param name="certInfo">
        ///   The certificate configuration.
        /// </param>
        /// <param name="enhancedKeyUsage">
        ///   The OID of the EKU that the certificate must define. Use <see cref="ServerAuthenticationOid"/> 
        ///   and <see cref="ClientAuthenticationOid"/> for server and client authentication 
        ///   respectively.
        /// </param>
        /// <returns>
        ///   The corresponding <see cref="X509Certificate2"/>, or <see langword="null"/> if a 
        ///   matching certificate cannot be loaded.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   <paramref name="certInfo"/> specifies both file and store certificate locations.
        /// </exception>
        public X509Certificate2? LoadCertificate(CertificateLocation? certInfo, string? enhancedKeyUsage = null) {
            if (certInfo is null) {
                LogCertificateNotFound(certInfo, GetEnhancedKeyUsageDisplayName(enhancedKeyUsage));
                return null;
            }

            X509Certificate2? certificate = null;

            if (certInfo.IsFileCert && certInfo.IsStoreCert) {
                throw new InvalidOperationException("Multiple certificate sources specified.");
            }
            else if (certInfo.IsFileCert) {
                var rootPath = _options.CertificateRootPath ?? AppContext.BaseDirectory;
                var certificatePath = Path.Combine(rootPath, certInfo.Path!);

#if NET8_0_OR_GREATER
                if (certInfo.KeyPath != null) {
                    var certificateKeyPath = Path.Combine(rootPath, certInfo.KeyPath);
                    certificate = GetCertificate(certificatePath);

                    if (certificate != null) {
                        certificate = LoadCertificateKey(certificate, certificateKeyPath, certInfo.Password);
                    }
                    else {
                        throw new InvalidOperationException($"The certificate file at '{certificatePath}' can not be found, contains malformed data or does not contain a certificate.");
                    }

                    if (certificate != null) {
                        if (OperatingSystem.IsWindows()) {
                            certificate = PersistKey(certificate);
                        }
                    }
                    else {
                        throw new InvalidOperationException($"The certificate key file at '{certificateKeyPath}' can not be found, contains malformed data or does not contain a PEM encoded key in PKCS8 format.");
                    }
                }
#endif

                if (certificate == null) {
                    certificate = new X509Certificate2(certificatePath, certInfo.Password);
                }

                if (certificate != null && enhancedKeyUsage != null && !HasEnhancedKeyUsage(certificate, enhancedKeyUsage)) {
                    certificate = null;
                }
            }
            else if (certInfo.IsStoreCert) {
                certificate = LoadFromStoreCert(certInfo, enhancedKeyUsage);
            }

            if (certificate == null) {
                LogCertificateNotFound(certInfo, GetEnhancedKeyUsageDisplayName(enhancedKeyUsage));
            }
            else {
                LogCertificateLoaded(certificate.Subject, certificate.Thumbprint, GetEnhancedKeyUsageDisplayName(enhancedKeyUsage));
            }

            return certificate;
        }


        /// <summary>
        /// Loads a certificate from the specified path.
        /// </summary>
        /// <param name="certificatePath">
        ///   The path to the certificate file.
        /// </param>
        /// <returns>
        ///   The corresponding <see cref="X509Certificate2"/>, or <see langword="null"/> if the 
        ///   <paramref name="certificatePath"/> does not contain a certificate.
        /// </returns>
        private static X509Certificate2? GetCertificate(string certificatePath) {
            if (X509Certificate2.GetCertContentType(certificatePath) == X509ContentType.Cert) {
                return new X509Certificate2(certificatePath);
            }

            return null;
        }


#if NET8_0_OR_GREATER

        /// <summary>
        /// Loads the private key for the specified certificate.
        /// </summary>
        /// <param name="certificate">
        ///   The certificate.
        /// </param>
        /// <param name="keyPath">
        ///   The path to the certificate key file.
        /// </param>
        /// <param name="password">
        ///   The password for the certificate key file, or <see langword="null"/> if the key file 
        ///   is not password-protected.
        /// </param>
        /// <returns>
        ///   A new <see cref="X509Certificate2"/> instance that contains the private key.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   The private key does not use a known algorithm.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   The private key cannot be loaded.
        /// </exception>
        private static X509Certificate2 LoadCertificateKey(X509Certificate2 certificate, string keyPath, string? password) {
            // OIDs for the certificate key types.
            const string RSAOid = "1.2.840.113549.1.1.1";
            const string DSAOid = "1.2.840.10040.4.1";
            const string ECDsaOid = "1.2.840.10045.2.1";

            // Duplication is required here because there are separate CopyWithPrivateKey methods for each algorithm.
            var keyText = File.ReadAllText(keyPath);
            switch (certificate.PublicKey.Oid.Value) {
                case RSAOid: {
                        using var rsa = RSA.Create();
                        ImportKeyFromFile(rsa, keyText, password);

                        try {
                            return certificate.CopyWithPrivateKey(rsa);
                        }
                        catch (Exception ex) {
                            throw CreateErrorGettingPrivateKeyException(keyPath, ex);
                        }
                    }
                case ECDsaOid: {
                        using var ecdsa = ECDsa.Create();
                        ImportKeyFromFile(ecdsa, keyText, password);

                        try {
                            return certificate.CopyWithPrivateKey(ecdsa);
                        }
                        catch (Exception ex) {
                            throw CreateErrorGettingPrivateKeyException(keyPath, ex);
                        }
                    }
                case DSAOid: {
                        using var dsa = DSA.Create();
                        ImportKeyFromFile(dsa, keyText, password);

                        try {
                            return certificate.CopyWithPrivateKey(dsa);
                        }
                        catch (Exception ex) {
                            throw CreateErrorGettingPrivateKeyException(keyPath, ex);
                        }
                    }
                default:
                    throw new InvalidOperationException($"Unknown algorithm for certificate with public key type '{certificate.PublicKey.Oid.Value}'.");
            }

            InvalidOperationException CreateErrorGettingPrivateKeyException(string keyPath, Exception ex) {
                return new InvalidOperationException($"Error getting private key from '{keyPath}'.", ex);
            }
        }


        /// <summary>
        /// Imports a private key from PEM-encoded text.
        /// </summary>
        /// <param name="asymmetricAlgorithm">
        ///   The asymmetric algorithm to import the key into.
        /// </param>
        /// <param name="keyText">
        ///   The PEM-encoded key text.
        /// </param>
        /// <param name="password">
        ///   The password for the key, or <see langword="null"/> if the key is not 
        ///   password-protected.
        /// </param>
        private static void ImportKeyFromFile(AsymmetricAlgorithm asymmetricAlgorithm, string keyText, string? password) {
            if (password == null) {
                asymmetricAlgorithm.ImportFromPem(keyText);
            }
            else {
                asymmetricAlgorithm.ImportFromEncryptedPem(keyText, password);
            }
        }

#endif


        /// <summary>
        /// Persists the private key for the specified certificate.
        /// </summary>
        /// <param name="certificate">
        ///   The certificate.
        /// </param>
        /// <returns>
        ///   A new <see cref="X509Certificate2"/> instance that contains the persisted private key.
        /// </returns>
        /// <remarks>
        ///   This is required on Windows when loading a certificate key from a non-PFX file as per 
        ///   https://github.com/dotnet/runtime/issues/23749.
        /// </remarks>
        private static X509Certificate2 PersistKey(X509Certificate2 certificate) {
            var certificateBytes = certificate.Export(X509ContentType.Pkcs12, "");
            return new X509Certificate2(certificateBytes, "", X509KeyStorageFlags.DefaultKeySet);
        }


        /// <summary>
        /// Loads a certificate from a certificate store.
        /// </summary>
        /// <param name="certLocation">
        ///   The certificate location.
        /// </param>
        /// <param name="enhancedKeyUsage">
        ///   The OID of the EKU that the certificate must have.
        /// </param>
        /// <returns>
        ///   The certificate, or <see langword="null"/> if no matching certificate was found and 
        ///   <see cref="CertificateLocation.AllowInvalid"/> is <see langword="true"/>.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   No matching certificate was found and <see cref="CertificateLocation.AllowInvalid"/> 
        ///   is <see langword="false"/>.
        /// </exception>
        private static X509Certificate2? LoadFromStoreCert(CertificateLocation certLocation, string? enhancedKeyUsage) {
            var subject = certLocation.Subject!;
            var storeName = string.IsNullOrEmpty(certLocation.Store) ? StoreName.My.ToString() : certLocation.Store;
            var storeLocation = StoreLocation.CurrentUser;

            var location = certLocation.Location;
            if (!string.IsNullOrEmpty(location)) {
                storeLocation = (StoreLocation) Enum.Parse(typeof(StoreLocation), location, ignoreCase: true);
            }

            var allowInvalid = certLocation.AllowInvalid ?? false;

            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            // Try and find the certificate by subject name first, then by thumbprint.

            var findBySubjectName = store.Certificates.Find(X509FindType.FindBySubjectName, subject, !allowInvalid)
                .OfType<X509Certificate2>()
                .Where(x => enhancedKeyUsage == null || HasEnhancedKeyUsage(x, enhancedKeyUsage))
                .Where(x => x.HasPrivateKey)
                .OrderByDescending(x => x.NotAfter);

            X509Certificate2? foundCertificate = null;

            foreach (var cert in findBySubjectName) {
                // Pick the first one if there's no exact match as a fallback to substring default.
                foundCertificate ??= cert;

                if (cert.GetNameInfo(X509NameType.SimpleName, true).Equals(subject, StringComparison.OrdinalIgnoreCase)) {
                    // Exact match
                    return cert;
                }
            }

            if (foundCertificate != null) {
                return foundCertificate;
            }

            // No subject name match, try thumbprint.

            var findByThumbprint = store.Certificates.Find(X509FindType.FindByThumbprint, subject, !allowInvalid)
                .OfType<X509Certificate2>()
                .Where(x => enhancedKeyUsage == null || HasEnhancedKeyUsage(x, enhancedKeyUsage))
                .Where(x => x.HasPrivateKey)
                .OrderByDescending(x => x.NotAfter);

            foreach (var cert in findByThumbprint) {
                if (string.Equals(cert.Thumbprint, subject, StringComparison.OrdinalIgnoreCase)) {
                    return cert;
                }
            }

            if (foundCertificate == null) {
                throw new InvalidOperationException($"The requested certificate '{subject}' could not be found in {storeLocation}/{storeName}.");
            }

            return foundCertificate;
        }


        /// <summary>
        /// Checks whether the specified certificate has the specified enhanced key usage.
        /// </summary>
        /// <param name="certificate">
        ///   The certificate.
        /// </param>
        /// <param name="enhancedKeyUsage">
        ///   The OID of the enhanced key usage to check for.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the certificate has the specified enhanced key usage or 
        ///   <see langword="false"/> otherwise.
        /// </returns>
        private static bool HasEnhancedKeyUsage(X509Certificate2 certificate, string enhancedKeyUsage) {
            if (enhancedKeyUsage == null) {
                return true;
            }

            var hasEkuExtension = false;

            foreach (var extension in certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()) {
                hasEkuExtension = true;
                foreach (var oid in extension.EnhancedKeyUsages) {
                    if (string.Equals(oid.Value, enhancedKeyUsage, StringComparison.Ordinal)) {
                        return true;
                    }
                }
            }

            return !hasEkuExtension;
        }


        /// <summary>
        /// Gets the display name for the specified enhanced key usage OID.
        /// </summary>
        /// <param name="oid">
        ///   The OID.
        /// </param>
        /// <returns>
        ///   The display name.
        /// </returns>
        private static string? GetEnhancedKeyUsageDisplayName(string? oid) {
            if (oid is null) {
                return null;
            }

            return oid switch {
                ServerAuthenticationOid => "Server Authentication",
                ClientAuthenticationOid => "Client Authentication",
                _ => oid
            };
        }


        [LoggerMessage(1, LogLevel.Debug, @"Certificate loaded: Subject=""{subject}"", Thumbprint=""{thumbprint}"", EnhancedKeyUsage=""{enhancedKeyUsage}""")]
        partial void LogCertificateLoaded(string subject, string thumbprint, string? enhancedKeyUsage);


        [LoggerMessage(2, LogLevel.Debug, @"Certificate not found: {config}, EnhancedKeyUsage=""{enhancedKeyUsage}""")]
        partial void LogCertificateNotFound(CertificateLocation? config, string? enhancedKeyUsage);

    }
}
