using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA512
    {
        private const string source = "Hestia.Security";
        private const string sha512 = "8F5DD5C38BC4FBC0F00758FE00E34C4891F7492CDA2CFE5A588BB6C806836FCAC3A7ABB3155519B393060D7B3A41F941CD63446CF497F5DE5F450A1EE134A4EA";
        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.SHA512(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha512, Convert.ToHexString(output));
        }
    }
}