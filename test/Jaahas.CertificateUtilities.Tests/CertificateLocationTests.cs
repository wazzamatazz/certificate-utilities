using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

#nullable disable warnings

namespace Jaahas.CertificateUtilities.Tests {

    [TestClass]
    public class CertificateLocationTests {

        public TestContext TestContext { get; set; }


        [DataTestMethod]
        [DataRow(@"cert:\CurrentUser\My\0123456789abcdef0123456789abcdef01234567")]
        [DataRow(@"CERT:\LOCALMACHINE\MY\CN=MyCert, O=MyOrg")]
        [DataRow(@"Cert:/LocalMachine/My/MyCert")]
        public void ShouldParseCertificateStoreLocationFromPath(string path) {
            var location = CertificateLocation.CreateFromPath(path);
            Assert.IsTrue(location.IsStoreCertificate);
            Assert.IsFalse(location.IsFileCertificate);
        }


        [DataTestMethod]
        [DataRow(@"C:\certs\mycert.pfx")]
        [DataRow(@"mycert.pem")]
        [DataRow(@"Cert:/LocalMachine")] // Incorrectly-specified store path
        public void ShouldNotParseCertificateStoreLocationFromPath(string path) {
            var location = CertificateLocation.CreateFromPath(path);
            Assert.IsFalse(location.IsStoreCertificate);
            Assert.IsTrue(location.IsFileCertificate);
        }


        [DataTestMethod]
        // Should resolve ASP.NET Core development certificate
        [DataRow(@"cert:\CurrentUser\My\localhost", true, CertificateLoader.ServerAuthenticationOid)]
        // Should resolve ISRG Root X1 (i.e. Let's Encrypt RSA root certificate)
        [DataRow(@"cert:\CurrentUser\Root\ISRG Root X1", false, null)]
        public void ShouldLoadCertificateFromStore(string path, bool requirePrivateKey, string? eku) {
            var location = CertificateLocation.CreateFromPath(path);
            location.RequirePrivateKey = requirePrivateKey;
            var loader = new CertificateLoader();
            var cert = loader.LoadCertificate(location, eku);
            Assert.IsNotNull(cert);
        }


        [DataTestMethod]
        [DataRow(@"cert:\CurrentUser\My\does_not_exist")]
        [DataRow(@"cert:\CurrentUser\Root\ISRG Root X1")] // Private key not available
        public void ShouldNotLoadCertificateFromStore(string path) {
            var location = CertificateLocation.CreateFromPath(path);
            var loader = new CertificateLoader();
            var cert = loader.LoadCertificate(location);
            Assert.IsNull(cert);
        }


        [TestMethod]
        public void ShouldLoadCertificateFromPfx() {
            var tempDir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            tempDir.Create();

            try {
                var cert = CreateSelfSignedCertificate();
                var password = RandomNumberGenerator.GetString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@£$%^&*()-_=+?.,#~'/\\|`", 24);
                var certFile = new FileInfo(Path.Combine(tempDir.FullName, "mycert.pfx"));
                File.WriteAllBytes(certFile.FullName, cert.Export(X509ContentType.Pfx, password));

                var location = CertificateLocation.CreateFromPath(certFile.FullName);
                location.Password = password;

                var loader = new CertificateLoader();
                var loadedCert = loader.LoadCertificate(location, "1.3.6.1.5.5.7.3.2"); // Client authentication
                Assert.IsNotNull(loadedCert);
                Assert.IsTrue(loadedCert.HasPrivateKey);
            }
            finally {
                tempDir.Delete(true);
            }
        }


        [TestMethod]
        public void ShouldLoadCertificateAndEncryptedPrivateKeyFromPem() {
            var tempDir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            tempDir.Create();

            try {
                var cert = CreateSelfSignedCertificate();
                var password = RandomNumberGenerator.GetString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@£$%^&*()-_=+?.,#~'/\\|`", 24);

                var certFile = new FileInfo(Path.Combine(tempDir.FullName, "mycert.pem"));
                File.WriteAllText(certFile.FullName, cert.ExportCertificatePem());

                var keyFile = new FileInfo(Path.Combine(tempDir.FullName, "mycert.key"));
                File.WriteAllText(keyFile.FullName, cert.GetRSAPrivateKey().ExportEncryptedPkcs8PrivateKeyPem(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 30000)));

                var location = CertificateLocation.CreateFromPath(certFile.FullName);
                location.KeyPath = keyFile.FullName;
                location.Password = password;

                var loader = new CertificateLoader();
                var loadedCert = loader.LoadCertificate(location, "1.3.6.1.5.5.7.3.2"); // Client authentication
                Assert.IsNotNull(loadedCert);
                Assert.IsTrue(loadedCert.HasPrivateKey);
            }
            finally {
                tempDir.Delete(true);
            }
        }


        [TestMethod]
        public void ShouldLoadCertificateAndUnencryptedPrivateKeyFromPem() {
            var tempDir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            tempDir.Create();

            try {
                var cert = CreateSelfSignedCertificate();

                var certFile = new FileInfo(Path.Combine(tempDir.FullName, "mycert.pem"));
                File.WriteAllText(certFile.FullName, cert.ExportCertificatePem());

                var keyFile = new FileInfo(Path.Combine(tempDir.FullName, "mycert.key"));
                File.WriteAllText(keyFile.FullName, cert.GetRSAPrivateKey().ExportPkcs8PrivateKeyPem());

                var location = CertificateLocation.CreateFromPath(certFile.FullName);
                location.KeyPath = keyFile.FullName;

                var loader = new CertificateLoader();
                var loadedCert = loader.LoadCertificate(location, CertificateLoader.ClientAuthenticationOid); // Client authentication
                Assert.IsNotNull(loadedCert);
                Assert.IsTrue(loadedCert.HasPrivateKey);
            }
            finally {
                tempDir.Delete(true);
            }
        }


        [TestMethod]
        public void ShouldLoadCertificateWithoutPrivateKeyFromPem() {
            var tempDir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            tempDir.Create();

            try {
                var cert = CreateSelfSignedCertificate();

                var certFile = new FileInfo(Path.Combine(tempDir.FullName, "mycert.pem"));
                File.WriteAllText(certFile.FullName, cert.ExportCertificatePem());

                var location = CertificateLocation.CreateFromPath(certFile.FullName);

                var loader = new CertificateLoader();
                var loadedCert = loader.LoadCertificate(location, CertificateLoader.ClientAuthenticationOid);
                Assert.IsNotNull(loadedCert);
                Assert.IsFalse(loadedCert.HasPrivateKey);
            }
            finally {
                tempDir.Delete(true);
            }
        }


        private X509Certificate2 CreateSelfSignedCertificate() {
            var csr = new CertificateRequest($"CN={TestContext.TestName}", RSA.Create(3072), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var ekus = new OidCollection() {
                Oid.FromOidValue(CertificateLoader.ClientAuthenticationOid, OidGroup.EnhancedKeyUsage) // Client authentication
            };
            csr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, false));
            csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

            return csr.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(7));
        }

    }

}
