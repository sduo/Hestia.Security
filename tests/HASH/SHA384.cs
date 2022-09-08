using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.HASH
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA384
    {
        private const string source = "Hestia.Security";
        private const string sha384 = "F0B40C42382ED8C308F525E33F550C46F5091CE4ADF8CEED8F13C7CF2A0A18C24D2C4FD859AFBDA236F90E3ABE57942D";
        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.HASH.SHA384(Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(sha384, Convert.ToHexString(output));
        }
    }
}