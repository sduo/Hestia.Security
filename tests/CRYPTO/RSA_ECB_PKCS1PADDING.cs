using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class RSA_ECB_PKCS1PADDING
    {
        private const string source = "Hestia.Security";
        private const string pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiuFRppdx3Ap3CJv2I/1UPAOHiappVYF0qLO8BJ6m+KghE72rOPxv8G4myOnkZHwl99TV3Q7f7/btKMi3L6MljvW3GGCCRjLd9oQY3tg8ocxBh7N9DUbhtdOdEYedj39a0MeR9+lPOnbYe0NUDNII5hsurAc5L3B7/hZfRTSdYIVyUWE+5/IhKUk7b3js/hRHAnzF0GdmRZQ1Qp+FrmGvwtIwHy2r0EWyXVc3Uff5bs8vLmnGnN/vGPKH821mFXcE8q/kVMbim6/FQMaMlw2ultz+lC1T4SG+h+RoYGG9DrKhmdpUDDmQyJGZy05Fimf1BclU/JQ9/olvVDPawLSL+wIDAQAB";
        private const string key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCK4VGml3HcCncIm/Yj/VQ8A4eJqmlVgXSos7wEnqb4qCETvas4/G/wbibI6eRkfCX31NXdDt/v9u0oyLcvoyWO9bcYYIJGMt32hBje2DyhzEGHs30NRuG1050Rh52Pf1rQx5H36U86dth7Q1QM0gjmGy6sBzkvcHv+Fl9FNJ1ghXJRYT7n8iEpSTtveOz+FEcCfMXQZ2ZFlDVCn4WuYa/C0jAfLavQRbJdVzdR9/luzy8uacac3+8Y8ofzbWYVdwTyr+RUxuKbr8VAxoyXDa6W3P6ULVPhIb6H5GhgYb0OsqGZ2lQMOZDIkZnLTkWKZ/UFyVT8lD3+iW9UM9rAtIv7AgMBAAECggEAJuOMOSF8RRj7FwKRLKfB4CI+4FpDL6nV8G2P7x079TIjPQNmAEmT0NgPbUAtb8Ph3+GN115Ub74Nz9dQkHrXSA5fLGjN4flZdS+tRS144Pewu96TXFXmW0N73o5CnQ2U8RSJN8nxoRXpba6/SO3BhynCanKFXVbaqZ47JEZk8UNTKzeocoX0D+fZ1Fnm8LnL8ASpmzJGR7rBRXhRpeYahGsOYqlK9WYRhNEVuf99jgR9FTTJCr9+b+ffP+x0jZq2+aChwNXQtW65N7YC0xnhOX433/9IPS7yNzUYtzUDLYZerOpzA+wV0AKDSFModKKdoi4stWm8Byq6KWGIxHC2KQKBgQDHJ6JL8pUpCZ3MCMIWBPZMbH7DHFmx8lYguNoi8vdi7YonHCOU9LTwJM4MgTt+atJeU7/gZleGNITfnap9+uUr1tazuobJPjxy+6q2s6ikgwGEtv1YQVsUMoriOMZgHCuxjt0MXfTYji83F8q4bRzruecahS2+PJAhLGmqCJprswKBgQCyhWCuTxNnWPhA5Y5/8gb8vmV+2gbOeVpXsH6U7W3EkGc1c/QlAdDC9jeKEESEtB/QhEKnOqlXuLLG1tCwfCw+VnpcVe4i5zvVedCeG736lMLpiUbw5a7VYWCHJdwnkype8mo/+3OLv20WhD7qC0MRNXSALeuoZuDFHGduN54amQKBgC4+o88i60P2ObARMJBQYqjoYJ8JzEIn1ZwPkIehB5TvN69RN2n1ULaatUXuFFSMlYDVza5b1WMSevA5+kb6pZCCeKSPYZEFZKAGlGOMYFKjIQ0iOL3vnyiXe+x/5oCWygaW9/lRL/PBQHF4ktg0bgzGxEVCO5b7FTS+zWJwUPtFAoGAEMQcB2Lf1KXzcszcbEHDzDrpd1dsqjmVdYTa7ou58msJdmi0dkFMZPMQ1kOe28O69S9mvyPwQY/UIn6MTPbshNJEXaWoXtjOssblA+RhHEaaY6qD4h4AJIQnt6mjmofkw9QKjIXGHUrWKPY0nnB+VQBrN5qYdlFrLLf1MtHAZIkCgYEAg94PRlFbpOKGb77qdtuSdqFy3bE8Q71nv0oKn2EBbuwXqlhKS+cxNV8P15tpR+bJw2uUbwcd37FtFwPDQB4oBbwQmS0mMAQt9THXqRrs7+oe+O9+hOO1YYj8pYWTXaMLsdF8aYBcggguapGYYYY7C5N4DFM31HtA3/32ghzAAbw=";
        

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.RSA_ECB_PKCS1PADDING_DECRYPT(Convert.FromBase64String(pub), Security.CRYPTO.RSA_ECB_PKCS1PADDING_ENCRYPT(Convert.FromBase64String(key), Encoding.UTF8.GetBytes(source)));
            Assert.AreEqual(source, Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test2()
        {
            (byte[] key, byte[] pub) = Security.Utility.RSA_GENKEY();
            byte[] output = Security.CRYPTO.RSA_ECB_PKCS1PADDING_DECRYPT(pub, Security.CRYPTO.RSA_ECB_PKCS1PADDING_ENCRYPT(key, Encoding.UTF8.GetBytes(source)));
            Assert.AreEqual(source, Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test3()
        {
            (byte[] key, byte[] pub) = Security.Utility.RSA_GENKEY();
            var k = PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded());
            var p = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub)));
            byte[] output = Security.CRYPTO.RSA_ECB_PKCS1PADDING_DECRYPT(p, Security.CRYPTO.RSA_ECB_PKCS1PADDING_ENCRYPT(k, Encoding.UTF8.GetBytes(source)));
            Assert.AreEqual(source, Encoding.UTF8.GetString(output));
        }
    }
}