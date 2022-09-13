using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.Utility
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class  Concat
    {
        private static readonly string[] source = new string[] { "Hestia", "security", "hestia", "Security"  };

        [TestMethod]
        public void Test1()
        {
            Assert.AreEqual("HestiaSecurityhestiasecurity", Security.Utility.OrdinalSortConcat(source),false);
        }

        [TestMethod]
        public void Test2()
        {
            Assert.AreEqual("Hestia.Security.hestia.security", Security.Utility.OrdinalSortConcat(".",source), false);
        }

        [TestMethod]
        public void Test3()
        {
            Assert.AreEqual("HestiahestiasecuritySecurity", Security.Utility.OrdinalIgnoreCaseSortConcat(source), false);
        }

        [TestMethod]
        public void Test4()
        {
            Assert.AreEqual("Hestia.hestia.security.Security", Security.Utility.OrdinalIgnoreCaseSortConcat(".",source), false);
        }

        [TestMethod]
        public void Test5()
        {
            Assert.AreEqual("HestiasecurityhestiaSecurity", Security.Utility.Concat(source), false);
        }

        [TestMethod]
        public void Test6()
        {
            Assert.AreEqual("Hestia.security.hestia.Security", Security.Utility.Concat(".",source), false);
        }

        [TestMethod]
        public void Test7()
        {
            Assert.AreEqual("HestiasecurityhestiaSecurity", Security.Utility.Concat(source,null,null), false);
        }
    }
}
