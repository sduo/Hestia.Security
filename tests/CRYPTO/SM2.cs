using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SM2
    {
        private const string source = "Hestia.Security";
        private const string key = "00AE98AB4AB44DEAAAC25F18752C1FECA08066D2DA9C6C9F965622D7C99BE501DF";
        private const string pub = "04E1882E25D275B40ACBD6DC1790157E2B0469E32BD78229FAFF8B62F6EEB43BED10102F03735921D42681ACD9F46256AA0A4AE788492514F17E33D23D54AA0062";


        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.SM2_DECRYPT(Convert.FromHexString(key), Security.CRYPTO.SM2_ENCRYPT(Convert.FromHexString(pub), Encoding.UTF8.GetBytes(source)));
            Assert.AreEqual(source, Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test3()
        {
            (byte[] key, byte[] pub) = Security.Utility.SM2_GENKEY();
            byte[] output = Security.CRYPTO.SM2_DECRYPT(key, Security.CRYPTO.SM2_ENCRYPT(pub, Encoding.UTF8.GetBytes(source)));
            Assert.AreEqual(source, Encoding.UTF8.GetString(output));
        }
    }
}