using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics.CodeAnalysis;

namespace Hestia.Security.Tests.Utility
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class BitConverter
    {
        [TestMethod]
        public void Test1()
        {            
            byte[] data = Security.Utility.BitConverterGetBytes(uint.MinValue);
            Assert.AreEqual(uint.MinValue, Security.Utility.BitConverterGetUInt(data));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(uint.MaxValue);
            Assert.AreEqual(uint.MaxValue, Security.Utility.BitConverterGetUInt(data));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(int.MinValue);
            Assert.AreEqual(int.MinValue, Security.Utility.BitConverterGetInt(data));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(int.MaxValue);
            Assert.AreEqual(int.MaxValue, Security.Utility.BitConverterGetInt(data));
        }

        [TestMethod]
        public void Test5()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(long.MinValue);
            Assert.AreEqual(long.MinValue, Security.Utility.BitConverterGetLong(data));
        }

        [TestMethod]
        public void Test6()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(long.MaxValue);
            Assert.AreEqual(long.MaxValue, Security.Utility.BitConverterGetLong(data));
        }

        [TestMethod]
        public void Test7()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(ulong.MinValue);
            Assert.AreEqual(ulong.MinValue, Security.Utility.BitConverterGetULong(data));
        }

        [TestMethod]
        public void Test8()
        {
            byte[] data = Security.Utility.BitConverterGetBytes(ulong.MaxValue);
            Assert.AreEqual(ulong.MaxValue, Security.Utility.BitConverterGetULong(data));
        }
    }
}
