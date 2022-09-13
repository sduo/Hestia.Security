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
    public sealed class PadBlockPadding
    {
        [TestMethod]
        public void Test1()
        {
            byte[] pad = Security.Utility.PadBlockPadding(0);
            Assert.AreEqual("2020202020202020202020202020202020202020202020202020202020202020", Convert.ToHexString(pad),true);
        }

        [TestMethod]
        public void Test2()
        {
            byte[] pad = Security.Utility.PadBlockPadding(32);
            Assert.AreEqual("2020202020202020202020202020202020202020202020202020202020202020", Convert.ToHexString(pad), true);
        }

        [TestMethod]
        public void Test3()
        {
            byte[] pad = Security.Utility.PadBlockPadding(16);
            Assert.AreEqual("10101010101010101010101010101010", Convert.ToHexString(pad), true);
        }

        [TestMethod]
        public void Test4()
        {
            byte[] pad = Security.Utility.PadBlockPadding(16,8);
            Assert.AreEqual("0808080808080808", Convert.ToHexString(pad), true);
        }
    }
}
