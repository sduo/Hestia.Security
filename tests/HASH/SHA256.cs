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

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.SHA256(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha256, Convert.ToHexString(output));
        }
    }
}