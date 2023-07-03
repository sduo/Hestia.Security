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
    public sealed class HMAC_MD5
    {
        private const string source = "Hestia.Security";
        private const string key = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")
        private const string hmac = "69453C2E8F91CB5B4F0D98A96BD972AE";

        // https://open.taobao.com/doc.htm?docId=101617&docType=1
        private const string taobao_key = "helloworld";
        private const string taobao_source = "app_key12345678fieldsnum_iid,title,nick,price,numformatjsonmethodtaobao.item.seller.getnum_iid11223344sessiontestsign_methodmd5timestamp2016-01-01 12:00:00v2.0";
        private const string taobao_hmac = "B4DDA503460D60A86B16E950E5D303E9";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.MAC.HMAC_MD5(Convert.FromHexString(key), Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(hmac, Convert.ToHexString(output));
        }
       
        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.MAC.HMAC_MD5(Encoding.UTF8.GetBytes(taobao_key), Encoding.UTF8.GetBytes(taobao_source));
            Assert.AreEqual(taobao_hmac, Convert.ToHexString(output));
        }
    }
}
