using System.Security.Cryptography.X509Certificates;

namespace Jaahas.CertificateUtilities;

/// <summary>
/// Extension methods for <see cref="CertificateLoader"/>.
/// </summary>
public static class CertificateLoaderExtensions {

    /// <summary>
    /// Loads a client certificate from the specified location.
    /// </summary>
    /// <param name="loader">
    ///   The certificate loader.
    /// </param>
    /// <param name="location">
    ///   The location to load the certificate from.
    /// </param>
    /// <returns>
    ///   The loaded client certificate, or <see langword="null"/> if the certificate could not be loaded.
    /// </returns>
    public static X509Certificate2? LoadClientCertificate(this CertificateLoader loader, CertificateLocation location)
        => loader?.LoadCertificate(location, CertificateLoader.ClientAuthenticationOid);

    
    /// <summary>
    /// Loads a server certificate from the specified location.
    /// </summary>
    /// <param name="loader">
    ///   The certificate loader.
    /// </param>
    /// <param name="location">
    ///   The location to load the certificate from.
    /// </param>
    /// <returns>
    ///   The loaded server certificate, or <see langword="null"/> if the certificate could not be loaded.
    /// </returns>
    public static X509Certificate2? LoadServerCertificate(this CertificateLoader loader, CertificateLocation location)
        => loader?.LoadCertificate(location, CertificateLoader.ServerAuthenticationOid);
    
}
