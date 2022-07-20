using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.AES
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class AES128_CBC_ZERO
    {
        private const string key = "F8C70091CDF5625BDEDB1AFA5FF4EC8A"; // Md5("AES128_CBC_ZERO")
        private const string iv = "AAE38E76915DAB68E8521C2FA968642F"; // Md5("Hestia")
        private const string encrypted = "70D35709BB896AD2C22C1FD01451164E";
        private const string decrypted = "Hestia.Security";

        [TestMethod]
        public void Test1()
        {
            byte[] output = Security.AES.AES128_CBC_ZERO_ENCRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Encoding.UTF8.GetBytes(decrypted));
            Assert.AreEqual(encrypted, Convert.ToHexString(output));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] output = Security.AES.AES128_CBC_ZERO_DECRYPT(Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(encrypted));
            Assert.AreEqual(decrypted, Encoding.UTF8.GetString(output));
        }
    }
}
