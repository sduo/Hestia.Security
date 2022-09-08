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

        [TestMethod]
        public void Test6()
        {
            byte[] output = Security.HASH.SM3(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sm3, Convert.ToHexString(output));
        }
    }
}