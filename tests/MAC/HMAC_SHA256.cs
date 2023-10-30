using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using static System.Net.Mime.MediaTypeNames;
using System.Xml.Linq;

namespace Hestia.Security.Tests.MAC
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class HMAC_SHA256
    {
        private const string source = "Hestia.Security";
        private const string key = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")
        private const string hmac = "BEA5A2A0FEC11B24F652FF88FC765AF321762E109923AA314252004B67085F45";

        // https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=4_3
        private const string wechat_key = "192006250b4c09247ec02edce69f6a2d";
        private const string wechat_source = "appid=wxd930ea5d5a258f4f&body=test&device_info=1000&mch_id=10000100&nonce_str=ibuaiVcKdpRxkhJA&key=192006250b4c09247ec02edce69f6a2d";
        private const string wechat_hmac = "6A9AE1657590FD6257D693A078E1C3E4BB6BA4DC30B23E0EE2496E54170DACD6";


        // https://open.dingtalk.com/document/robots/customize-robot-security-settings
        private const string dingtalk_secret = "SEC0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string dingtalk_timestamp = "1234567890987";
        private const string dingtalk_hmac = "DS4ksAxenBH2OvTFmGArI+u0ba8l5x9WZOdj6LHZzUo=";

        // https://open.gongyi.qq.com/docs/server_api/%E5%BC%80%E5%8F%91%E5%89%8D%E5%BF%85%E8%AF%BB/%E6%8E%A5%E5%8F%A3%E8%B0%83%E7%94%A8%E5%87%AD%E8%AF%81.html#%E5%BA%94%E7%94%A8%E7%AD%BE%E5%90%8D
        private const string tencent_gongyi_key = "secret1234567890secret1234567890";
        private const string tencent_gongyi_source = "Gy-H-Api-Appid=12345&Gy-H-Api-Nonce-Str=1234567890abcdef1234567890abcdef&Gy-H-Api-Timestamp=1650966683";
        private const string tencent_gongyi_hmac = "76D81D6C374C989111297C4EB3F804B274FD4093BA2E9B6255DAB30653DBE229";


        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.MAC.HMAC_SHA256(Convert.FromHexString(key), Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(hmac, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.MAC.HMAC_SHA256(Encoding.UTF8.GetBytes(wechat_key), Encoding.UTF8.GetBytes(wechat_source));
            Assert.AreEqual(wechat_hmac, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] output = Security.MAC.HMAC_SHA256(Encoding.UTF8.GetBytes(dingtalk_secret), Encoding.UTF8.GetBytes(Security.Utility.Concat("\n", dingtalk_timestamp, dingtalk_secret)));
            Assert.AreEqual(dingtalk_hmac, Convert.ToBase64String(output));           
        }

        [TestMethod]
        public void Test4()
        {
            byte[] output = Security.MAC.HMAC_SHA256(Encoding.UTF8.GetBytes(tencent_gongyi_key), Encoding.UTF8.GetBytes($"{tencent_gongyi_source}&key={tencent_gongyi_key}"));
            Assert.AreEqual(tencent_gongyi_hmac, Convert.ToHexString(output));
        }
    }
}
