using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
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

        // https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html
        // https://res.wx.qq.com/wxdoc/dist/assets/media/aes-sample.eae1f364.zip
        private const string wechat_key = "tiihtNczf5v6AKRyjwEUhQ==";
        private const string wechat_iv = "r7BXXKkLb8qrSNn05n0qiA==";
        private const string wechat_encrypted = "CiyLU1Aw2KjvrjMdj8YKliAjtP4gsMZMQmRzooG2xrDcvSnxIMXFufNstNGTyaGS9uT5geRa0W4oTOb1WT7fJlAC+oNPdbB+3hVbJSRgv+4lGOETKUQz6OYStslQ142dNCuabNPGBzlooOmB231qMM85d2/fV6ChevvXvQP8Hkue1poOFtnEtpyxVLW1zAo6/1Xx1COxFvrc2d7UL/lmHInNlxuacJXwu0fjpXfz/YqYzBIBzD6WUfTIF9GRHpOn/Hz7saL8xz+W//FRAUid1OksQaQx4CMs8LOddcQhULW4ucetDf96JcR3g0gfRK4PC7E/r7Z6xNrXd2UIeorGj5Ef7b1pJAYB6Y5anaHqZ9J6nKEBvB4DnNLIVWSgARns/8wR2SiRS7MNACwTyrGvt9ts8p12PKFdlqYTopNHR1Vf7XjfhQlVsAJdNiKdYmYVoKlaRv85IfVunYzO0IKXsyl7JCUjCpoG20f0a04COwfneQAGGwd5oa+T8yO5hzuyDb/XcxxmK01EpqOyuxINew==";
        private const string wechat_decrypted = "{\"openId\":\"oGZUI0egBJY1zhBYw2KhdUfwVJJE\",\"nickName\":\"Band\",\"gender\":1,\"language\":\"zh_CN\",\"city\":\"Guangzhou\",\"province\":\"Guangdong\",\"country\":\"CN\",\"avatarUrl\":\"http://wx.qlogo.cn/mmopen/vi_32/aSKcBBPpibyKNicHNTMM0qJVh8Kjgiak2AHWr8MHM4WgMEm7GFhsf8OYrySdbvAMvTsw3mo8ibKicsnfN5pRjl1p8HQ/0\",\"unionId\":\"ocMvos6NjeKLIBqg5Mr9QjxrP1FA\",\"watermark\":{\"timestamp\":1477314187,\"appid\":\"wx4f4bc4dec97d474b\"}}";

        // https://github.com/alipay/alipay-sdk-net-all/blob/master/v2/AlipaySDKNet.Standard/Util/AlipayEncrypt.cs
        // https://github.com/alipay/alipay-sdk-net-all/blob/master/v2/UnitTestNetCore/EncryptTest.cs
        private const string alipay_key = "aa4BtZ4tspm2wnXLb1ThQA==";
        private const string alipay_iv = "00000000000000000000000000000000";
        private const string alipay_encrypted = "ILpoMowjIQjfYMR847rnFQ==";
        private const string alipay_decrypted = "test1234567";

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

        [TestMethod]
        public void Test3()
        {
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_DECRYPT(Convert.FromBase64String(wechat_key), Convert.FromBase64String(wechat_iv), Convert.FromBase64String(wechat_encrypted));
            Assert.AreEqual(wechat_decrypted, Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_ENCRYPT(Convert.FromBase64String(wechat_key), Convert.FromBase64String(wechat_iv), Encoding.UTF8.GetBytes(wechat_decrypted));
            Assert.AreEqual(wechat_encrypted, Convert.ToBase64String(output));
        }

        [TestMethod]
        public void Test5()
        {
            var k = new ParametersWithIV(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(iv));
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_DECRYPT(k, Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test6()
        {
            var k = new ParametersWithIV(new KeyParameter(Convert.FromHexString(key)), Convert.FromHexString(iv));
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_ENCRYPT(k, Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test7()
        {
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_ENCRYPT(Convert.FromBase64String(alipay_key), Convert.FromHexString(alipay_iv), Encoding.UTF8.GetBytes(alipay_decrypted));
            Assert.AreEqual(alipay_encrypted, Convert.ToBase64String(output));
        }

        [TestMethod]
        public void Test8()
        {
            byte[] output = Security.CRYPTO.AES_CBC_PKCS7PADDING_DECRYPT(Convert.FromBase64String(alipay_key), Convert.FromHexString(alipay_iv), Convert.FromBase64String(alipay_encrypted));
            Assert.AreEqual(alipay_decrypted, Encoding.UTF8.GetString(output));
        }
    }
}