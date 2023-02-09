using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.Utility
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class BaseString
    {
        private const string source = "Hestia.Security";
        private const string target32 = "JBSXG5DJMEXFGZLDOVZGS5DZ";
        private const string target64 = "SGVzdGlhLlNlY3VyaXR5";
        private readonly Encoding encoding = Encoding.UTF8;

        [TestMethod]
        public void Test1()
        {
            Assert.AreEqual(target32, Security.Utility.ToBase32String(encoding.GetBytes(source)));
        }

        [TestMethod]
        public void Test2()
        {
            Assert.AreEqual(source, encoding.GetString( Security.Utility.FromBase32String(target32)));
        }

        [TestMethod]
        public void Test3()
        {
            Assert.AreEqual(source, encoding.GetString(Security.Utility.FromBase32String(string.Concat(target32,"="))));
        }

        [TestMethod]
        public void Test4()
        {
            Assert.AreEqual(target64, Security.Utility.ToBase64String(encoding.GetBytes(source)));
        }

        [TestMethod]
        public void Test5()
        {
            Assert.AreEqual(source, encoding.GetString(Security.Utility.FromBase64String(target64)));
        }

        [TestMethod]
        public void Test6()
        {
            Assert.AreEqual(source, encoding.GetString(Security.Utility.FromBase64String(string.Concat(target64, "="))));
        }

        [TestMethod]
        public void Test7()
        {
            Assert.AreEqual(target64, Convert.ToBase64String(encoding.GetBytes(source)));
        }

        [TestMethod]
        public void Test8()
        {
            Assert.AreEqual(source, encoding.GetString(Convert.FromBase64String(target64)));
        }

    }
}
