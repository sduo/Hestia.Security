using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES_CBC_NOPADDING
    {
        private const string key = "52EB6AD278A0AA5821EB756F441F63E9"; // Md5("AES_CBC_NOPADDING")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "F59375852070EA7F9D93BA9A05B2036E";
        private const string decrypted = "D65E412F66CBFCCECD445662E55932E5"; //MD5("Hestia.Security")

        // https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/api/Before_Develop/Technical_Plan.html
        // https://wximg.gtimg.com/shake_tv/mpwiki/cryptoDemo.zip
        private const string wechat_tpp_key = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C=";
        private const string wechat_tpp_appid = "wx5823bf96d3bd56c7";
        private const string wechat_tpp_xml = "<xml><ToUserName><![CDATA[wx5823bf96d3bd56c7]]></ToUserName>\n<FromUserName><![CDATA[mycreate]]></FromUserName>\n<CreateTime>1409659813</CreateTime>\n<MsgType><![CDATA[text]]></MsgType>\n<Content><![CDATA[hello]]></Content>\n<MsgId>4561255354251345929</MsgId>\n<AgentID>218</AgentID>\n</xml>";
        private const string wechat_tpp_encrypted = "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q==";
        private const string wechat_tpp_decrypted = "<xml><ToUserName><![CDATA[mycreate]]></ToUserName><FromUserName><![CDATA[wx582测试一下中文的情况，消息长度是按字节来算的396d3bd56c7]]></FromUserName><CreateTime>1348831860</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[this is a test]]></Content><MsgId>1234567890123456</MsgId></xml>";

        // https://open.dingtalk.com/document/org/configure-event-subcription
        // https://github.com/open-dingtalk/dingtalk-callback-Crypto/blob/main/DingTalkEncryptor.cs
        private const string dingtalk_key = "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus=";
        private const string dingtalk_appid = "dingxxxxxx";       
        private const string dingtalk_encrypted = "X1VSe9cTJUMZu60d3kyLYTrBq5578ZRJtteU94wG0Q4Uk6E/wQYeJRIC0/UFW5Wkya1Ihz9oXAdLlyC9TRaqsQ==";
        private const string dingtalk_decrypted = "success";


        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.CRYPTO.AES_CBC_NOPADDING_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] key = Convert.FromBase64String(wechat_tpp_key);
            byte[] iv = key[..16];
            byte[] output = Security.Utility.TrimBlockPadding(Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(key, iv, Convert.FromBase64String(wechat_tpp_encrypted)));            
            int index = Security.Utility.BitConverterGetInt(output[16..20]) + 20;
            Assert.AreEqual(string.Join(":", wechat_tpp_appid, wechat_tpp_xml),string.Join(":", Encoding.UTF8.GetString(output[index..]), Encoding.UTF8.GetString(output[20..index])));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] key = Convert.FromBase64String(wechat_tpp_key);
            byte[] iv = key[..16];
            byte[] rand = Guid.NewGuid().ToByteArray();
            byte[] appid = Encoding.UTF8.GetBytes(wechat_tpp_appid);
            byte[] decrypted = Encoding.UTF8.GetBytes(wechat_tpp_decrypted);
            byte[] length = Security.Utility.BitConverterGetBytes(decrypted.Length);
            byte[] pad = Security.Utility.PadBlockPadding(rand.Length + length.Length + appid.Length + decrypted.Length);
            byte[] data = new byte[rand.Length + length.Length + appid.Length + decrypted.Length + pad.Length];
            Array.Copy(rand,0, data,0, rand.Length);
            Array.Copy(length, 0, data, rand.Length, length.Length);
            Array.Copy(decrypted, 0, data, rand.Length + length.Length, decrypted.Length);
            Array.Copy(appid, 0, data, rand.Length + length.Length + decrypted.Length, appid.Length);
            Array.Copy(pad, 0, data, rand.Length + length.Length + appid.Length + decrypted.Length, pad.Length);
            byte[] encrypted = Security.CRYPTO.AES_CBC_NOPADDING_ENCRYPT(key, iv, data);
            byte[] output = Security.Utility.TrimBlockPadding(Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(key, iv, encrypted));
            int index = Security.Utility.BitConverterGetInt(output[16..20]) + 20;
            Assert.AreEqual(string.Join(":", wechat_tpp_appid, wechat_tpp_decrypted), string.Join(":", Encoding.UTF8.GetString(output[index..]), Encoding.UTF8.GetString(output[20..index])));
        }

        [TestMethod]
        public void Test5()
        {
            byte[] key =  Convert.FromBase64String(dingtalk_key);
            byte[] iv = key[..16];
            byte[] output = Security.Utility.TrimBlockPadding(Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(key, iv, Convert.FromBase64String(dingtalk_encrypted)));
            int index = Security.Utility.BitConverterGetInt(output[16..20]) + 20;
            Assert.AreEqual(string.Join(":", dingtalk_appid, dingtalk_decrypted), string.Join(":", Encoding.UTF8.GetString(output[index..]), Encoding.UTF8.GetString(output[20..index])));
        }

        [TestMethod]
        public void Test6()
        {
            byte[] key = Convert.FromBase64String(dingtalk_key);
            byte[] iv = key[..16];
            byte[] rand = Guid.NewGuid().ToByteArray();
            byte[] appid = Encoding.UTF8.GetBytes(dingtalk_appid);
            byte[] decrypted = Encoding.UTF8.GetBytes(dingtalk_decrypted);
            byte[] length = Security.Utility.BitConverterGetBytes(decrypted.Length);
            byte[] pad = Security.Utility.PadBlockPadding(rand.Length + length.Length + appid.Length + decrypted.Length);
            byte[] data = new byte[rand.Length + length.Length + appid.Length + decrypted.Length + pad.Length];
            Array.Copy(rand, 0, data, 0, rand.Length);
            Array.Copy(length, 0, data, rand.Length, length.Length);
            Array.Copy(decrypted, 0, data, rand.Length + length.Length, decrypted.Length);
            Array.Copy(appid, 0, data, rand.Length + length.Length + decrypted.Length, appid.Length);
            Array.Copy(pad, 0, data, rand.Length + length.Length + appid.Length + decrypted.Length, pad.Length);
            byte[] encrypted = Security.CRYPTO.AES_CBC_NOPADDING_ENCRYPT(key, iv, data);
            byte[] output = Security.Utility.TrimBlockPadding(Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(key, iv, encrypted));
            int index = Security.Utility.BitConverterGetInt(output[16..20]) + 20;
            Assert.AreEqual(string.Join(":", dingtalk_appid, dingtalk_decrypted), string.Join(":", Encoding.UTF8.GetString(output[index..]), Encoding.UTF8.GetString(output[20..index])));
        }
    }
}