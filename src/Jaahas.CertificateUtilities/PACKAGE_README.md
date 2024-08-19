# Jaahas.CertificateUtilties

This package provides a set of utilities for working with X.509 certificates.


# Installation

Add a NuGet package reference to [Jaahas.CertificateUtilities](https://www.nuget.org/packages/Jaahas.CertificateUtilities).


# Getting Started

The package contains assemblies for both .NET Framework 4.7.2 and .NET 8.0. Some functionality is only available in the .NET 8.0 version.


## Certificate Loader

The `CertificateLoader` class provides a simple way to load client or server certificates from the file system or from the Windows certificate store. It is largely based on Kestrel's [internal certificate loader](https://github.com/dotnet/aspnetcore/blob/main/src/Servers/Kestrel/Core/src/Internal/Certificates/CertificateConfigLoader.cs).

```csharp
var loader = new CertificateLoader();

var certificateFromStore = loader.LoadCertificate(new CertificateLocation() {
    Subject = "MyCertificate",
    Store = "My",
    Location = "CurrentUser"
}, enhancedKeyUsage: CertificateLoader.ServerAuthenticationOid);

var certificateFromFile = loader.LoadCertificate(new CertificateLocation() {
    Path = @"C:\path\to\certificate.pfx",
    Password = "<PFX password>"
});
```

On .NET 8.0 and higher, it is also possible to load certificates and private keys from separate PEM-encoded files:

```csharp
var loader = new CertificateLoader();

var certificate = loader.LoadCertificate(new CertificateLocation() {
    Path = @"C:\path\to\certificate.pem",
    KeyPath = @"C:\path\to\private-key.pem",
    Password = "<private key password>"
});
```
