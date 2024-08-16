namespace Jaahas.CertificateUtilities {

    /// <summary>
    /// Options for <see cref="CertificateLoader"/>.
    /// </summary>
    public sealed class CertificateLoaderOptions {

        /// <summary>
        /// The base path to use when loading certificates from the file system.
        /// </summary>
        public string? CertificateRootPath { get; set; }

    }

}
