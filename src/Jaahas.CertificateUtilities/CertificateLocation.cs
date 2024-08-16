using System.ComponentModel.DataAnnotations;

namespace Jaahas.CertificateUtilities {

    /// <summary>
    /// Describes a file- or store-based X.509 client certificate.
    /// </summary>
    public sealed class CertificateLocation : IValidatableObject {

        /// <summary>
        /// Returns <see langword="true"/> if no certificate has been specified.
        /// </summary>
        public bool IsEmpty => !IsFileCert && !IsStoreCert;

        // File

        /// <summary>
        /// Returns <see langword="true"/> if a file system-based certificate has been specified.
        /// </summary>
        public bool IsFileCert => !string.IsNullOrEmpty(Path);

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
        public bool IsStoreCert => !string.IsNullOrEmpty(Subject) || !string.IsNullOrEmpty(Thumbprint);

        /// <summary>
        /// The subject of the store certificate to use.
        /// </summary>
        public string? Subject { get; set; }

        /// <summary>
        /// The thumbprint of the store certificate to use.
        /// </summary>
        public string? Thumbprint { get; set; }

        /// <summary>
        /// The name of the certificate store to use.
        /// </summary>
        public string? Store { get; set; }

        /// <summary>
        /// The location of the certificate store to use.
        /// </summary>
        public string? Location { get; set; }

        /// <summary>
        /// When set, specifies if store-based certificates can be used even if they are invalid.
        /// </summary>
        public bool? AllowInvalid { get; set; }


        /// <inheritdoc/>
        public override string ToString() {
            var parts = new List<string>();

            if (IsFileCert) {
                if (!string.IsNullOrWhiteSpace(Path)) {
                    parts.Add($"Path={Path}");
                }
#if NET8_0_OR_GREATER
                if (!string.IsNullOrWhiteSpace(KeyPath)) {
                    parts.Add($"KeyPath={KeyPath}");
                }
#endif
            }
            else if (IsStoreCert) {
                if (!string.IsNullOrWhiteSpace(Subject)) {
                    parts.Add($"Subject={Subject}");
                }
                if (!string.IsNullOrWhiteSpace(Store)) {
                    parts.Add($"Store={Store}");
                }
                if (!string.IsNullOrWhiteSpace(Location)) {
                    parts.Add($"Location={Location}");
                }
            }

            parts.Add($"AllowInvalid={(AllowInvalid ?? false)}");

            return $"({string.Join(", ", parts)})";
        }


        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) {
            if (IsFileCert && IsStoreCert) {
                yield return new ValidationResult("Certificate configuration can specify a file certificate or a store certificate, but not both.", new[] { nameof(Path), nameof(Subject) });
            }
        }

    }
}
