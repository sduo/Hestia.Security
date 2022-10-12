using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA256
    {
        private const string source = "Hestia.Security";
        private const string sha256 = "397E7E46D5134DC8CF39CA894AD45147E87827F5628407E859097B9037877650";

        // 财政电子票据对接报文规范-开票报文 > 附录B-消息摘要
        private const string cz_key = "TEST_APP_KEY";
        private const string cz_xml = "<?xml version='1.0' encoding='UTF-8'?><Invoice><Head><MsgNo>8901</MsgNo><Version>1.0</Version><AppId>KPQZDWB5629411</AppId><MsgId>20190522213800999</MsgId><DateTime>20190522213800999</DateTime><Resvered></Resvered></Head><Msg>PFZvdWNoZXI+PFBsYWNlQ29kZT4wMDE8L1BsYWNlQ29kZT48L1ZvdWNoZXI+</Msg></Invoice>";
        private const string cz_sha256 = "09be4a8404ae81630c4bc6fb6c58df816a724d48e7ff2dd22ff79d87e43f342a";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.SHA256(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha256, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {            
            byte[] output = Security.HASH.SHA256(Encoding.UTF8.GetBytes(string.Concat(cz_key, cz_xml)));
            Assert.AreEqual(cz_sha256, Convert.ToHexString(output),true);
        }
    }

}