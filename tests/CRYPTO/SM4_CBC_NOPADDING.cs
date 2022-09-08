using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SM4_CBC_NOPADDING
    {
        private const string key = "6144C79F107C1C0C4DA02A6F86B82684"; // Md5("SM4_CBC_NOPADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "2313854EB1C3927DFD49B2C97C13B9A2";
        private const string decrypted = "D65E412F66CBFCCECD445662E55932E5";

        // GM/T 0002-2012
        // http://www.gmbz.org.cn/main/bzlb.html
        private const string gb_key = "0123456789ABCDEFFEDCBA9876543210";
        private const string gb_iv = "00000000000000000000000000000000";
        private const string gb_encrypted = "681EDF34D206965E86B3E94F536E4246";
        private const string gb_decrypted = "0123456789ABCDEFFEDCBA9876543210";
        private const string gb_encrypted_1M = "595298C7C6FD271F0402F804C33D3F66";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.SM4_CBC_NOPADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.SM4_CBC_NOPADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] output = Security.CRYPTO.SM4_CBC_NOPADDING_ENCRYPT(Convert.FromHexString(gb_key), Convert.FromHexString(gb_iv), Convert.FromHexString(gb_decrypted));
            Assert.AreEqual(gb_encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] data = Convert.FromHexString(gb_decrypted);
            byte[] key = Convert.FromHexString(gb_key);
            byte[] iv = Convert.FromHexString(gb_iv);
            for (int i= 0; i < 1000000; ++i)
            {
                data = Security.CRYPTO.SM4_CBC_NOPADDING_ENCRYPT(key, iv, data);
            }            
            Assert.AreEqual(gb_encrypted_1M, Convert.ToHexString(data));
        }
    }
}