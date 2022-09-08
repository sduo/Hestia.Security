using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES_GCM_NOPADDING
    {
        private const string key = "6F07850E32A874CC5D97894A2EB4B347"; // Md5("AES_GCM_NOPADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "7A9ED42ED9BFDBDAE75F03D4E90CCECC93741E0F7CC2AA95BF55E0514CC5E228";
        private const string decrypted = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")  

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_GCM_NOPADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_GCM_NOPADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }
    }
}