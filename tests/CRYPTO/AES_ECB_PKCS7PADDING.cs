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
    public sealed class AES_ECB_PKCS7PADDING
    {
        private const string key = "C1B5BFCB645F3ADB6D30F0CCBFDFAB99"; // Md5("AES_ECB_PKCS7PADDING")
        private const string encrypted = "72E1953393F175D82D4E9F8FF765166A5A7998DC095F29CAE6305A56DF578CBC";
        private const string decrypted = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")

        private const string alipay_key = "CHARITY_ERC_2022";
        private const string alipay_decrypted = "123456789";
        private const string alipay_encrypted = "VtLDIlVi42erj5VycJbg6Q==";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_ENCRYPT(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_DECRYPT(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test5()
        {
            CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("AES128");
            byte[] key = generator.GenerateKey();
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_DECRYPT(key, Security.CRYPTO.AES_ECB_PKCS7PADDING_ENCRYPT(key, Convert.FromHexString(decrypted)));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }
        [TestMethod]
        public void Test6()
        {
            CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("AES192");
            byte[] key = generator.GenerateKey();
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_DECRYPT(key, Security.CRYPTO.AES_ECB_PKCS7PADDING_ENCRYPT(key, Convert.FromHexString(decrypted)));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test7()
        {
            CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("AES256");
            byte[] key = generator.GenerateKey();
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_DECRYPT(key, Security.CRYPTO.AES_ECB_PKCS7PADDING_ENCRYPT(key, Convert.FromHexString(decrypted)));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test8()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_ENCRYPT(Encoding.UTF8.GetBytes(alipay_key), Encoding.UTF8.GetBytes(alipay_decrypted));
            Assert.AreEqual(alipay_encrypted, Convert.ToBase64String(output));
        }

        [TestMethod]
        public void Test9()
        {
            byte[] output = Security.CRYPTO.AES_ECB_PKCS7PADDING_DECRYPT(Encoding.UTF8.GetBytes(alipay_key), Convert.FromBase64String(alipay_encrypted));
            Assert.AreEqual(alipay_decrypted, Encoding.UTF8.GetString(output));
        }
    }
}