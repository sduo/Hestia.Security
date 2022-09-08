using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class MD5
    {
        private const string source = "Hestia.Security";
        private const string md5 = "D65E412F66CBFCCECD445662E55932E5";         

        // https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=4_3
        private const string wechat_md5_source = "appid=wxd930ea5d5a258f4f&body=test&device_info=1000&mch_id=10000100&nonce_str=ibuaiVcKdpRxkhJA&key=192006250b4c09247ec02edce69f6a2d";
        private const string wechat_md5 = "9A0A8659F005D6984697E2CA0A9CF3B7";        

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.MD5(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(md5, Convert.ToHexString(output));
        }    

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.HASH.MD5(Encoding.UTF8.GetBytes(wechat_md5_source));
            Assert.AreEqual(wechat_md5, Convert.ToHexString(output));
        }        
    }
}