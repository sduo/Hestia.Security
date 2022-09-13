using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.SIGN
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SM3_WITH_SM2
    {
        private const string key = "40543E796C0290C871820187D2239F5148B0EAC9D08C87585619C4E82D003D76";
        private const string pub = "0410246565E7B7974535A47E413502AF1464136D970103362A75B3878A695BF8B9E0747212FDFEE61CCE8F6A8C1412DD1E2F54754753787AC369AE4B037DD0A27B"; 
        private const string source = "Hestia.Security";
        private const string signature = "3045022055E6350CC569A749638A56B5FE16B7A52F798D1C62C7C0A4CA9A71C9790C458B0221008B890AE85D6D0125A53DAD65BD14157270877E8ACAEFC391A34DA48A125DD1F7";

        [TestMethod]
        public void Test1()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SM3_WITH_SM2_SIGN(Convert.FromHexString(key), input);
            Assert.IsTrue(Security.SIGN.SM3_WITH_SM2_VERIFY(Convert.FromHexString(pub), input, signature));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            Assert.IsTrue(Security.SIGN.SM3_WITH_SM2_VERIFY(Convert.FromHexString(pub), input, Convert.FromHexString(signature)));
        }

        [TestMethod]
        public void Test3()
        {
            (byte[] key, byte[] pub) = Security.Utility.SM2_GENKEY();
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SM3_WITH_SM2_SIGN(key, input);
            Assert.IsTrue(Security.SIGN.SM3_WITH_SM2_VERIFY(pub, input, signature));
        }

        [TestMethod]
        public void Test4()
        {
            (byte[] key, byte[] pub) = Security.Utility.EC_GENKEY(Security.Utility.SM2P256V1_DOMAIN,true);
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SM3_WITH_SM2_SIGN(key, input);
            Assert.IsTrue(Security.SIGN.SM3_WITH_SM2_VERIFY(pub, input, signature));
        }

    }
}