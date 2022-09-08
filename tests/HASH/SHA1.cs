using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA1
    {
        private const string source = "Hestia.Security";
        private const string sha1 = "617E74E08F38BAD2488D63D00D38EE7E77D20975";

        // https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html
        private const string wechat_miniprogram_sha1_source = "{\"nickName\":\"Band\",\"gender\":1,\"language\":\"zh_CN\",\"city\":\"Guangzhou\",\"province\":\"Guangdong\",\"country\":\"CN\",\"avatarUrl\":\"http://wx.qlogo.cn/mmopen/vi_32/1vZvI39NWFQ9XM4LtQpFrQJ1xlgZxx3w7bQxKARol6503Iuswjjn6nIGBiaycAjAtpujxyzYsrztuuICqIM5ibXQ/0\"}HyVFkGl5F5OQWJZZaNzBBg==";
        private const string wechat_miniprogram_sha1 = "75E81CEDA165F4FFA64F4068AF58C64B8F54B88C";

        // https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/api/Before_Develop/Technical_Plan.html
        // https://wximg.gtimg.com/shake_tv/mpwiki/cryptoDemo.zip
        // TimeStamp、Token、Nonce、Encrypt
        private static readonly string[] wechat_tpp_sha1_source = new string[] { "1409659813", "QDG6eK", "1372623149", "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q==" };
        private const string wechat_tpp_sha1 = "477715d11cdb4164915debcba66cb864d751f3e6";

        // https://open.dingtalk.com/document/org/configure-event-subcription
        // https://github.com/open-dingtalk/dingtalk-callback-Crypto/blob/main/DingTalkEncryptor.cs
        // TimeStamp、Token、Nonce、Encrypt
        private static readonly string[] dingtalk_source = new string[] {"1605695694141", "tokenxxxx", "WelUQl6bCqcBa2fM","X1VSe9cTJUMZu60d3kyLYTrBq5578ZRJtteU94wG0Q4Uk6E/wQYeJRIC0/UFW5Wkya1Ihz9oXAdLlyC9TRaqsQ==" };
        private const string dingtalk_sha1 = "f36f4ba5337d426c7d4bca0dbcb06b3ddc1388fc";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.SHA1(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha1, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.HASH.SHA1(Encoding.UTF8.GetBytes(wechat_miniprogram_sha1_source));
            Assert.AreEqual(wechat_miniprogram_sha1, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test3()
        {            
            byte[] output = Security.HASH.SHA1(Encoding.ASCII.GetBytes(Security.Utility.SortConcat(wechat_tpp_sha1_source)));
            Assert.AreEqual(wechat_tpp_sha1, Convert.ToHexString(output),true);
        }

        [TestMethod]
        public void Test4()
        {
            byte[] output = Security.HASH.SHA1(Encoding.ASCII.GetBytes(Security.Utility.SortConcat(dingtalk_source)));
            Assert.AreEqual(dingtalk_sha1, Convert.ToHexString(output),true);
        }
    }
}