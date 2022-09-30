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
        [TestMethod]
        public void Test()
        {
            Security.CRYPTO.HXJZ("123ABC");
        }
    }
}
