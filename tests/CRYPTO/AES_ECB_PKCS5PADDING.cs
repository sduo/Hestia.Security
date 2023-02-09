using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES_ECB_PKCS5PADDING
    {
        private const string key = "B62EE6CCC1EF5FF4B143939A411EDA13"; // Md5("AES_ECB_PKCS5PADDING")
        private const string encrypted = "FB905D191B4E116A1EEEF6D993F8797CE8FAC833A40EC80251C3B006479C70BF";
        private const string decrypted = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")
               

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_ENCRYPT(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_DECRYPT(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test5()
        {
            CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("AES128");
            byte[] key = generator.GenerateKey();
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_DECRYPT(key, Security.CRYPTO.AES_ECB_PKCS5PADDING_ENCRYPT(key, Convert.FromHexString(decrypted)));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }
        [TestMethod]
        public void Test6()
        {
            CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("AES192");
            byte[] key = generator.GenerateKey();
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_DECRYPT(key, Security.CRYPTO.AES_ECB_PKCS5PADDING_ENCRYPT(key, Convert.FromHexString(decrypted)));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test7()
        {
            CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("AES256");
            byte[] key = generator.GenerateKey();
            byte[] output = Security.CRYPTO.AES_ECB_PKCS5PADDING_DECRYPT(key, Security.CRYPTO.AES_ECB_PKCS5PADDING_ENCRYPT(key, Convert.FromHexString(decrypted)));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }
    }
}