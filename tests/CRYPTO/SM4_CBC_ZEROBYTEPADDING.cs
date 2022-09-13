using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SM4_CBC_ZEROBYTEPADDING
    {
        private const string key = "ABE5FEB5035D574E0F351DE3BFAC7425"; // Md5("SM4_CBC_ZEROBYTEPADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "A0FAF4DDFC4341D9B9F6715BD98642C0";
        private const string decrypted = "Hestia.Security";
        

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.SM4_CBC_ZEROBYTEPADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.SM4_CBC_ZEROBYTEPADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test3()
        {
            var k = new ParametersWithIV(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(iv));
            byte[] output = Security.CRYPTO.SM4_CBC_ZEROBYTEPADDING_ENCRYPT(k, Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test4()
        {
            var k = new ParametersWithIV(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(iv));
            byte[] output = Security.CRYPTO.SM4_CBC_ZEROBYTEPADDING_DECRYPT(k, Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Encoding.UTF8.GetString(output));
        }
    }
}