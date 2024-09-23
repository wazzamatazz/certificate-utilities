using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Jaahas.CertificateUtilities {

    /// <summary>
    /// Describes a file- or store-based X.509 client certificate.
    /// </summary>
    public sealed partial class CertificateLocation : IValidatableObject {

        /// <summary>
        /// Returns <see langword="true"/> if no certificate has been specified.
        /// </summary>
        public bool IsEmpty => !IsFileCertificate && !IsStoreCertificate;

        // File

        /// <summary>
        /// Returns <see langword="true"/> if a file system-based certificate has been specified.
        /// </summary>
        public bool IsFileCertificate => !string.IsNullOrEmpty(Path);

#if NET8_0_OR_GREATER

        /// <summary>
        /// The path to the certificate file.
        /// </summary>
        public string? Path { get; set; }

        /// <summary>
        /// The path to the certificate's private key file.
        /// </summary>
        public string? KeyPath { get; set; }

        /// <summary>
        /// The password for the certificate file (if <see cref="Path"/> represents a PFX file) or 
        /// the private key file (if <see cref="KeyPath"/> has been specified).
        /// </summary>
        public string? Password { get; set; }

#else

        /// <summary>
        /// The path to the certificate PFX file.
        /// </summary>
        public string? Path { get; set; }

        /// <summary>
        /// The password for the certificate PFX file.
        /// </summary>
        public string? Password { get; set; }

#endif

        // Cert store

        /// <summary>
        /// Returns <see langword="true"/> if a certificate store-based certificate has been specified.
        /// </summary>
        public bool IsStoreCertificate => !string.IsNullOrEmpty(Subject);

        /// <summary>
        /// The subject name or thumbprint of the store certificate to use.
        /// </summary>
        /// <remarks>
        ///   The <see cref="Subject"/> can be a thumbprint, an X.500 distinguished name, or a 
        ///   partial subject name for the certificate.
        /// </remarks>
        public string? Subject { get; set; }

        /// <summary>
        /// The name of the certificate store to use.
        /// </summary>
        public string? Store { get; set; }

        /// <summary>
        /// The location of the certificate store to use.
        /// </summary>
        public string? Location { get; set; }

        /// <summary>
        /// When set, specifies if a store-based certificate can be used even if it is invalid
        /// (for example, if it has expired).
        /// </summary>
        /// <remarks>
        /// 
        /// <para>
        ///   This property is ignored unless <see cref="IsStoreCertificate"/> is <see langword="true"/>.
        /// </para>
        /// 
        /// <para>
        ///   If not set, invalid certificates are not allowed.
        /// </para>
        /// 
        /// </remarks>
        public bool? AllowInvalid { get; set; }

        /// <summary>
        /// When set, specifies if a store-based certificate can be used even if its private key 
        /// is not available.
        /// </summary>
        /// <remarks>
        /// 
        /// <para>
        ///   This property is ignored unless <see cref="IsStoreCertificate"/> is <see langword="true"/>.
        /// </para>
        /// 
        /// <para>
        ///   If not set, private keys are required.
        /// </para>
        /// 
        /// </remarks>
        public bool? RequirePrivateKey { get; set; }


        /// <inheritdoc/>
        public override string ToString() {
            var parts = new List<string>();

            if (IsFileCertificate) {
                if (!string.IsNullOrWhiteSpace(Path)) {
                    parts.Add($"Path={Path}");
                }
#if NET8_0_OR_GREATER
                if (!string.IsNullOrWhiteSpace(KeyPath)) {
                    parts.Add($"KeyPath={KeyPath}");
                }
#endif
            }
            else if (IsStoreCertificate) {
                if (!string.IsNullOrWhiteSpace(Subject)) {
                    parts.Add($"Subject={Subject}");
                }
                if (!string.IsNullOrWhiteSpace(Store)) {
                    parts.Add($"Store={Store}");
                }
                if (!string.IsNullOrWhiteSpace(Location)) {
                    parts.Add($"Location={Location}");
                }
                parts.Add($"AllowInvalid={(AllowInvalid ?? false)}");
                parts.Add($"RequirePrivateKey={(RequirePrivateKey ?? true)}");
            }

            return $"({string.Join(", ", parts)})";
        }


        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) {
            if (IsFileCertificate && IsStoreCertificate) {
                yield return new ValidationResult("Certificate configuration can specify a file certificate or a store certificate, but not both.", new[] { nameof(Path), nameof(Subject) });
            }
        }


#if NET8_0_OR_GREATER

        [GeneratedRegex(@"^CERT\:(?:\\|/)(?<location>.+?)(?:\\|/)(?<store>.+)(?:\\|/)(?<subject>.+)$", RegexOptions.IgnoreCase)]
        private static partial Regex GetCertificateStorePathPatcher();

#else

        /// <summary>
        /// Case-insensitive regex for matching the full path to a certificate in a certificate 
        /// store e.g. <c>cert:\CurrentUser\My\1234567890abcdef1234567890abcdef123456789</c>. Both 
        /// back- and forward-slashes can be used as path separators.
        /// </summary>
        private static readonly Regex s_certificateStorePathMatcher = new Regex(@"^CERT\:(?:\\|/)(?<location>.+?)(?:\\|/)(?<store>.+)(?:\\|/)(?<subject>.+)$", RegexOptions.IgnoreCase);

        private static Regex GetCertificateStorePathPatcher() => s_certificateStorePathMatcher;

#endif


        /// <summary>
        /// Parses a certificate location from a path string that can represent either a file 
        /// system location or a certificate store location.
        /// </summary>
        /// <param name="path">
        ///   The path string. This can be a file path or a path to a certificate in a certificate 
        ///   store. See the method remarks for more information.
        /// </param>
        /// <returns>
        ///   The parsed certificate location.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="path"/> is <see langword="null"/> or white space.
        /// </exception>
        /// <remarks>
        /// 
        /// <para>
        ///   Certificate store locations can be specified using the following format: 
        ///   <c>cert:\{location}\{store}\{thumbprint_or_subject}</c>
        /// </para>
        /// 
        /// <para>
        ///   The format is case-insensitive and supports both back- and forward-slashes as path 
        ///   separators. Paths that do not match the above format are treated as file paths.
        /// </para>
        /// 
        /// <para>
        ///   Notes:
        /// </para>
        /// 
        /// <list type="bullet">
        ///   <item>
        ///     <c>{location}</c> can be <c>CurrentUser</c> or <c>LocalMachine</c>.
        ///   </item>
        ///   <item>
        ///     <c>{store}</c> is the name of the certificate store to use. See <see cref="System.Security.Cryptography.X509Certificates.StoreName"/> 
        ///     for valid values.
        ///   </item>
        ///   <item>
        ///     <c>{thumbprint_or_subject}</c> is the thumbprint, distinguished name, or partial 
        ///     subject name for the certificate.
        ///   </item>
        /// </list>
        /// 
        /// <para>
        ///   Examples:
        /// </para>
        /// 
        /// <list type="bullet">
        ///   <item>
        ///     <c>cert:\CurrentUser\My\0123456789abcdef0123456789abcdef01234567</c> (find by thumbprint)
        ///   </item>
        ///   <item>
        ///     <c>cert:\LocalMachine\My\CN=MyCert, O=MyOrg</c> (find by distinguished name)
        ///   </item>
        ///   <item>
        ///     <c>cert:\LocalMachine\My\MyCert</c> (find by partial subject name)
        ///   </item>
        /// </list>
        /// 
        /// 
        /// 
        /// </remarks>
        public static CertificateLocation CreateFromPath(string path) {
            if (string.IsNullOrWhiteSpace(path)) {
                throw new ArgumentOutOfRangeException(nameof(path));
            }

            var match = GetCertificateStorePathPatcher().Match(path);
            if (match.Success) {
                return new CertificateLocation() {
                    Location = match.Groups["location"].Value,
                    Store = match.Groups["store"].Value,
                    Subject = match.Groups["subject"].Value
                };
            }

            return new CertificateLocation() {
                Path = path
            };
        }

    }
}
