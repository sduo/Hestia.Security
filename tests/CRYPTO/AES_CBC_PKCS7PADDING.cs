using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES_CBC_PKCS7PADDING
    {
        private const string key = "E3231A81B478F634D9C59B4A025656B1"; // Md5("AES_CBC_PKCS7PADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "FBC4354CA9A108BABC3DE57BD9D6A7A7";
        private const string decrypted = "Hestia.Security";        

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted,Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted,Encoding.UTF8.GetString(output));
        }
    }
}