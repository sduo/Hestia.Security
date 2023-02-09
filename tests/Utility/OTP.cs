using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.Utility
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class OTP
    {
        private const string key = "JBSXG5DJMEXFGZLDOVZGS5DZ"; // Base32 encode from "Hestia.Security"
        private const long ticks = 626851008000000000;
        private const int otp = 181870;
        private const string hash = "C144184EE9A2FF16A198964EC0A4828D94C12627";

        [TestMethod]
        public void Test1()
        {
            Assert.AreEqual(0,  Security.Utility.GetTimeBasedCounter(DateTimeOffset.UnixEpoch.Ticks, 30));
        }

        [TestMethod]
        public void Test2()
        {
            Assert.AreEqual(0, Security.Utility.GetTimeBasedCounter(DateTimeOffset.UtcNow.Ticks, 0));
        }

        [TestMethod]
        public void Test3()
        {
            Assert.AreEqual(18316800, Security.Utility.GetTimeBasedCounter(ticks, 30));
        }

        [TestMethod]
        public void Test4()
        {
            Assert.AreEqual(9158400, Security.Utility.GetTimeBasedCounter(ticks, 60));
        }

        [TestMethod]
        public void Test5()
        {
            Assert.AreEqual("181870", Security.Utility.FormatOTP(otp, "000000"));
        }

        [TestMethod]
        public void Test6()
        {
            Assert.AreEqual("181 870", Security.Utility.FormatOTP(otp, "000 000"));
        }

        [TestMethod]
        public void Test7()
        {
            Assert.AreEqual(379689110, Security.Utility.TruncateOTP(Convert.FromHexString(hash)));
        }

        [TestMethod]
        public void Test8()
        {
            Assert.AreEqual("181870", Security.Utility.TOTP(key,0,"000000"));
        }

        [TestMethod]
        public void Test9()
        {
            Assert.AreEqual("330007", Security.Utility.TOTP(key, ticks, 30, "000000"));
        }

    }
}
