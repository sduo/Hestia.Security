using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.AES
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES128_CBC_PKCS7
    {
        private const string key = "645E97284A52997F9F222513DA1CF016"; // Md5("AES128_CBC_PKCS7")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "E2DB989309A36EAFE0A3627F269F6DAC";
        private const string decrypted = "Hestia.Security";        

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.AES.AES128_CBC_PKCS7_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted,Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.AES.AES128_CBC_PKCS7_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted,Encoding.UTF8.GetString(output));
        }

        [TestMethod]
        public void Test3()
        {
            var key = Convert.FromBase64String("tiihtNczf5v6AKRyjwEUhQ==");
            var iv = Convert.FromBase64String("r7BXXKkLb8qrSNn05n0qiA==");
            var encrypted = Convert.FromBase64String("CiyLU1Aw2KjvrjMdj8YKliAjtP4gsMZMQmRzooG2xrDcvSnxIMXFufNstNGTyaGS9uT5geRa0W4oTOb1WT7fJlAC+oNPdbB+3hVbJSRgv+4lGOETKUQz6OYStslQ142dNCuabNPGBzlooOmB231qMM85d2/fV6ChevvXvQP8Hkue1poOFtnEtpyxVLW1zAo6/1Xx1COxFvrc2d7UL/lmHInNlxuacJXwu0fjpXfz/YqYzBIBzD6WUfTIF9GRHpOn/Hz7saL8xz+W//FRAUid1OksQaQx4CMs8LOddcQhULW4ucetDf96JcR3g0gfRK4PC7E/r7Z6xNrXd2UIeorGj5Ef7b1pJAYB6Y5anaHqZ9J6nKEBvB4DnNLIVWSgARns/8wR2SiRS7MNACwTyrGvt9ts8p12PKFdlqYTopNHR1Vf7XjfhQlVsAJdNiKdYmYVoKlaRv85IfVunYzO0IKXsyl7JCUjCpoG20f0a04COwfneQAGGwd5oa+T8yO5hzuyDb/XcxxmK01EpqOyuxINew==");
            var decrypted = "{\"openId\":\"oGZUI0egBJY1zhBYw2KhdUfwVJJE\",\"nickName\":\"Band\",\"gender\":1,\"language\":\"zh_CN\",\"city\":\"Guangzhou\",\"province\":\"Guangdong\",\"country\":\"CN\",\"avatarUrl\":\"http://wx.qlogo.cn/mmopen/vi_32/aSKcBBPpibyKNicHNTMM0qJVh8Kjgiak2AHWr8MHM4WgMEm7GFhsf8OYrySdbvAMvTsw3mo8ibKicsnfN5pRjl1p8HQ/0\",\"unionId\":\"ocMvos6NjeKLIBqg5Mr9QjxrP1FA\",\"watermark\":{\"timestamp\":1477314187,\"appid\":\"wx4f4bc4dec97d474b\"}}";
            byte[] output = Security.AES.AES128_CBC_PKCS7_DECRYPT(key, iv, encrypted);
            Assert.AreEqual(decrypted, Encoding.UTF8.GetString(output));
        }        
    }
}