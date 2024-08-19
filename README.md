# Jaahas.CertificateUtilities

This repository contains libraries that simplify the use of X.509 certificates in .NET applications.


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


# Building the Solution

The repository uses [Cake](https://cakebuild.net/) for cross-platform build automation. The build script allows for metadata such as a build counter to be specified when called by a continuous integration system such as TeamCity.

A build can be run from the command line using the [build.ps1](/build.ps1) PowerShell script or the [build.sh](/build.sh) Bash script. For documentation about the available build script parameters, see [build.cake](/build.cake).


# Software Bill of Materials

To generate a Software Bill of Materials (SBOM) for the repository in [CycloneDX](https://cyclonedx.org/) XML format, run [build.ps1](./build.ps1) or [build.sh](./build.sh) with the `--target BillOfMaterials` parameter.

The resulting SBOM is written to the `artifacts/bom` folder.
