using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class HASH
    {
        private const string source = "Hestia.Security";
        private const string md5 = "D65E412F66CBFCCECD445662E55932E5"; 
        private const string sha1 = "617E74E08F38BAD2488D63D00D38EE7E77D20975";
        private const string sha256 = "397E7E46D5134DC8CF39CA894AD45147E87827F5628407E859097B9037877650";
        private const string sha384 = "F0B40C42382ED8C308F525E33F550C46F5091CE4ADF8CEED8F13C7CF2A0A18C24D2C4FD859AFBDA236F90E3ABE57942D";
        private const string sha512 = "8F5DD5C38BC4FBC0F00758FE00E34C4891F7492CDA2CFE5A588BB6C806836FCAC3A7ABB3155519B393060D7B3A41F941CD63446CF497F5DE5F450A1EE134A4EA";


        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.MD5(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(md5, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.HASH.SHA1(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha1, Convert.ToHexString(output));
        }


        [TestMethod]
        public void Test3()
        {
            byte[] output = Security.HASH.SHA256(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha256, Convert.ToHexString(output));
        }


        [TestMethod]
        public void Test4()
        {
            byte[] output = Security.HASH.SHA384(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha384, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test5()
        {
            byte[] output = Security.HASH.SHA512(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha512, Convert.ToHexString(output));
        }
    }
}
