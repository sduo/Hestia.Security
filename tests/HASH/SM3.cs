using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SM3
    {
        private const string source = "Hestia.Security";
        private const string sm3 = "F6FD3C909701A51424414F8E340771B882E178DD13F8D701E58DADBCD7E199C0";

        // 财政电子票据对接报文规范-开票报文
        // 财政电子票据对接报文规范-入账报文
        // 财政电子票据对接报文规范-数据交换报文
        // 附录B-消息摘要
        private const string cz_key = "TEST_APP_KEY";
        private const string cz_xml = "<?xml version='1.0' encoding='UTF-8'?><Invoice><Head><MsgNo>8901</MsgNo><Version>1.0</Version><AppId>KPQZDWB5629411</AppId><MsgId>20190522213800999</MsgId><DateTime>20190522213800999</DateTime><Resvered></Resvered></Head><Msg>PFZvdWNoZXI+PFBsYWNlQ29kZT4wMDE8L1BsYWNlQ29kZT48L1ZvdWNoZXI+</Msg></Invoice>";
        private const string cz_sm3 = "34a137b8bba3b6eefbee72eac423eddefc67048ba9e1fa725139ad596e8dedf4";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.SM3(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sm3, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.HASH.SM3(Encoding.UTF8.GetBytes(string.Concat(cz_key, cz_xml)));
            Assert.AreEqual(cz_sm3, Convert.ToHexString(output),true);
        }
    }
}