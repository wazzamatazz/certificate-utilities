namespace Jaahas.CertificateUtilities {

    /// <summary>
    /// Options for <see cref="CertificateLoader"/>.
    /// </summary>
    public sealed class CertificateLoaderOptions {

        /// <summary>
        /// The base path to use when loading certificates from the file system.
        /// </summary>
        /// <remarks>
        ///   If <see cref="CertificateRootPath"/> is <see langword="null"/> or white space, the 
        ///   <see cref="CertificateLoader"/> will use <see cref="AppContext.BaseDirectory"/> as 
        ///   the default root path.
        /// </remarks>
        public string? CertificateRootPath { get; set; }

    }

}
