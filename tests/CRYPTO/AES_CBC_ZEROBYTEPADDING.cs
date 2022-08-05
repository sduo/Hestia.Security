using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES_CBC_ZEROBYTEPADDING
    {
        private const string key = "F0A36A05F50FB12602AEBA331DA52E77"; // Md5("AES_CBC_ZEROBYTEPADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "FCB5ADA59C6C9D69DCB9B1A43C59511B";
        private const string decrypted = "Hestia.Security";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_CBC_ZEROBYTEPADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_CBC_ZEROBYTEPADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Encoding.UTF8.GetString(output));
        }
    }
}
