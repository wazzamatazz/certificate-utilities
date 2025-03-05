# Jaahas.CertificateUtilities

This package provides a set of utilities for working with X.509 certificates.


# Installation

Add a NuGet package reference to [Jaahas.CertificateUtilities](https://www.nuget.org/packages/Jaahas.CertificateUtilities).


# Getting Started

The package contains assemblies for both .NET Framework 4.7.2 and .NET 8.0. Some functionality is only available in the .NET 8.0 version.


## Certificate Loader

The `CertificateLoader` class provides a simple way to load client or server certificates from the file system or from a certificate store. It is largely based on Kestrel's [internal certificate loader](https://github.com/dotnet/aspnetcore/blob/main/src/Servers/Kestrel/Core/src/Internal/Certificates/CertificateConfigLoader.cs).

```csharp
var loader = new CertificateLoader();

// Load from a store.
var certificateFromStore = loader.LoadCertificate(new CertificateLocation() {
    Subject = "MyCertificate",
    Store = "My",
    Location = "CurrentUser"
});

// Load from a store and specify a required enhanced key usage.
var certificateWithEkuFromStore = loader.LoadCertificate(new CertificateLocation() {
    Subject = "MyCertificate",
    Store = "My",
    Location = "CurrentUser"
}, enhancedKeyUsage: CertificateLoader.ServerAuthenticationOid);

// Load from a store using an extension method to specify a required enhanced key usage.
var certificateWithEkuFromStore = loader.LoadServerCertificate(new CertificateLocation() {
    Subject = "MyCertificate",
    Store = "My",
    Location = "CurrentUser"
});

// Load from a file.
var certificateFromFile = loader.LoadCertificate(new CertificateLocation() {
    Path = @"C:\path\to\certificate.pfx",
    Password = "<PFX password>"
});
```

When loading a certificate from a certificate store you can also specify if expired or invalid certificates can be returned, and whether or not the private key for the certificate must also be available. By default, expired or invalid certificates are not returned and the private key is required.

```csharp
var location = new CertificateLocation() {
    Subject = "MyCertificate",
    Store = "My",
    Location = "CurrentUser",
    AllowInvalid = true,
    RequirePrivateKey = false
};
```

You can also create a `CertificateLocation` instance from a path to a certificate file or certificate store location using the static `CertificateLocation.CreateFromPath` method. The method will parse your path to determine if it is a file system path or a certificate store path: 

```csharp
// Create from file path
var location1 = CertificateLocation.CreateFromPath(@"C:\path\to\certificate.pfx");

// Create from certificate store location
var location2 = CertificateLocation.CreateFromPath(@"cert:\CurrentUser\My\localhost");
```

Certificate store locations can be specified using the format `cert:\{location}\{store}\{subject_or_thumbprint_or_distinguished_name}`. The format is case-insensitive and can use both back- and forward-slashes as path separators.

When creating a `CertificateLocation` using `CreateFromPath`, remember that you may still need to set properties such as `Password` or `KeyPath` separately.

On .NET 8.0 and higher, it is also possible to load certificates and private keys from separate PEM-encoded files:

```csharp
var loader = new CertificateLoader();

var certificate = loader.LoadCertificate(new CertificateLocation() {
    Path = @"C:\path\to\certificate.pem",
    KeyPath = @"C:\path\to\private-key.pem",
    Password = "<private key password>"
});
```
