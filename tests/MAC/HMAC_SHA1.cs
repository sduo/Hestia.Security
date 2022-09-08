using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.MAC
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class HMAC_SHA1
    {
        private const string source = "Hestia.Security"; 
        private const string key = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")
        private const string hmac = "7E251B0F96D94960CE4FCE2A2FC599F5C4472D44";

        // https://help.aliyun.com/document_detail/315526.html
        // 20220906
        // 原文档构造待签名字符串stringToSign 有两处有问题：
        // 原文档值：GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeDedicatedHosts%26Format%3DXML%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D3ee8c1b8-xxxx-xxxx-xxxx-xxxxxxxxx%26SignatureVersion%3D1.0%26Timestamp%3D2016-02-23T12%253A46%253A24Z%26Version%3D2014-05-26        
        // 1. SignatureNonce 错误
        // 文档值：3ee8c1b8-xxxx-xxxx-xxxx-xxxxxxxxx
        // 正确值：3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf
        // 2. Action 错误
        // 文档值：DescribeDedicatedHosts
        // 正确值：DescribeRegions
        // 正确的值可以根据 https://help.aliyun.com/document_detail/148140.html 中相关的示例得出
        private const string aliyun_key = "testsecret&";        
        private const string aliyun_source = "GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeRegions%26Format%3DXML%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf%26SignatureVersion%3D1.0%26Timestamp%3D2016-02-23T12%253A46%253A24Z%26Version%3D2014-05-26";
        private const string aliyun_hmac = "OLeaidS1JvxuMvnyHOwuJ+uX5qY="; //38B79A89D4B526FC6E32F9F21CEC2E27EB97E6A6

        

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.MAC.HMAC_SHA1(Convert.FromHexString(key), Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(hmac, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.MAC.HMAC_SHA1(Encoding.UTF8.GetBytes(aliyun_key), Encoding.UTF8.GetBytes(aliyun_source));
            Assert.AreEqual(aliyun_hmac, Convert.ToBase64String(output));
        }        
    }
}