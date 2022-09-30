using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class HXJZ
    {
        private const string encrypted = "自由爱国公正平等法治和谐法治自由公正敬业公正民主文明诚信自由平等和谐公正平等公正和谐法治平等法治文明公正敬业法治自由法治敬业";
        private const string decrypted = "Hestia.Security";

        [TestMethod]
        public void Test1()
        {
            Assert.AreEqual(encrypted, Security.CRYPTO.HXJZ_ENCRYPT(decrypted));
        }

        [TestMethod]
        public void Test2()
        {
            Assert.AreEqual(decrypted, Security.CRYPTO.HXJZ_DECRYPT(encrypted));
        }
    }
}
