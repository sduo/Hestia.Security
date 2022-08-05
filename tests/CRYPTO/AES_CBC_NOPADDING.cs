using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES_CBC_NOPADDING
    {
        private const string key = "52EB6AD278A0AA5821EB756F441F63E9"; // Md5("AES_CBC_NOPADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "F59375852070EA7F9D93BA9A05B2036E";
        private const string decrypted = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_CBC_NOPADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

    }
}
