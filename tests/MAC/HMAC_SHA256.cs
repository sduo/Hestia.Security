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
    }
}
