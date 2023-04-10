using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.SIGN
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA1_WITH_RSA
    {
        private const string source = "Hestia.Security";
        private const string pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkFuJsqGjmof5r1pMImfNNEhDg6qGiXhm6Noo5dlMkWhRdR6kkrlsLIJQQKOtDLT/3JI328LFH1CNmhAoo2K94L7x0SpMVdYrCRsz7Ue97jQqwd6mAyD2vegNhnUV+akubuvC5u8SNKMA7bRw/TRl/kA692Cbmr9SuOdnVclfjYyfN+r0YeUfSxSMnVm6LNbZLwfcWq75iatCaNoSn4p9/F4x7/+S96XiDqVP5qrRBBdoew1yHFfVqQQOB7Ovf5QSc9rpsFbChIp11k7xVm0rKfBxrmtImU5Rx5kM/0L9xtO134fqlt/+XzXg9jAtHyqUEPBIdRjIzQk3t3NI2pqaNwIDAQAB";
        private const string key = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCQW4myoaOah/mvWkwiZ800SEODqoaJeGbo2ijl2UyRaFF1HqSSuWwsglBAo60MtP/ckjfbwsUfUI2aECijYr3gvvHRKkxV1isJGzPtR73uNCrB3qYDIPa96A2GdRX5qS5u68Lm7xI0owDttHD9NGX+QDr3YJuav1K452dVyV+NjJ836vRh5R9LFIydWbos1tkvB9xarvmJq0Jo2hKfin38XjHv/5L3peIOpU/mqtEEF2h7DXIcV9WpBA4Hs69/lBJz2umwVsKEinXWTvFWbSsp8HGua0iZTlHHmQz/Qv3G07Xfh+qW3/5fNeD2MC0fKpQQ8Eh1GMjNCTe3c0jampo3AgMBAAECggEABhjXqAPLtSspEI7vyEQ6Fos2zsjVBdlf/1W3hH25DispxZiVuty6BOc8HH7NQEwkwlwqn82KJdhxIqCsFrqE6okmDX+L2dRB3RCZENyG2Ri69ZVBzcAGq96xM4yecP0ESQsMIFTYoACCeYe1ffxIkoSD+Q7Lg62xAL5FTwpCTughSkBaihDX9sA019ZupTDrK8utblk5dD6ivKYQEJE02EcwjIIrLZNQdNBnQDsOubuJIes1b+QQwiKxNN2D6nNTzjO63v97J6mDA49nzlcBac/Un6rXRsQvYGOsB2n+RL6Fwki0X02i7sK/jbE8An5TtIpECH1jowz+O+GDcC9JAQKBgQDODdVx/15uTxbXHs4IM8d1no4PwTDBok5N8k/k6BA8+TM46e6dWTVKnGm4BRkzt3DaguoDHa+cYGXr822NYFb6sZHMGKgLlpwByc5GjCsgTCFA11pOpyuna9ZULyjk2n1oqt+QZD1pvlvNH9rMbvWmNA+uzB19+qU1jYaYJulnDwKBgQCzWUjbr+awSC7y5pEDw9QqKEIxxsAWGmglu0ZpxihduwakVbjxNAkwlyXCvFxwdp1pNeMfils3OvsMqdlMTHELx4H8yQmFb7gxuuQ9fuZR0dsscn3WSGG6NnwGNyD4fCvljBson/PC1Zkfonf+rcVfijKspGknREZLVNx5yx3aWQKBgFxClW+ViBKcFv37LQU/Ke/gLnufZNVOdwEvndZAkgS7D9RL6itJ5jKiFjPvFHmziTRNqbn7cMXz467iMAs9N7TIDR/1akjGBtRGJ7YuzKCJddoykpzk/QbZof3Pn9/YdI6I89ETEOxn73LI8I7Yn+TrKpp5ijr+Hzr7Q2idA6TBAoGANngnaJFDvsYtfBgKctpG1Ybkk7mJHS1n9A2slPNZzx2+JqriQF9NazR8g2gxqvZbWFjFYg7jJSMEnBP5qvKMYsd08xEbkysbBf980jB4QuE5b4ZWMX5KMAPcJwcXPGB59H1Ywj3SCppUpwbw6qhcCWgve79zMDnMH5TmYRcPOgECgYB8TjIHiYha4CZa98OC9FH9IkPczOn8xZMPuFZYnirmbIOw4LjqimQicYCse1NQ5SoWrCUMOwBE8tnEtw6fMWO/keKl0JRDIP/RzfJTZvg+AHtN2/GruVi8loX4DkHAg3u5wC3a/fDDWKj7x0E1KOlsb11xeIisqHXR6PFyHHcx9Q==";
        private const string sha1_rsa_signature = "1BA7CFEDED976BA1BF47EE68CF14AB8F1E792F5A15D794DBF27771C98252FF1C7CE1F3C4674449E7C842D12B677EB5EE519CB5C5D053D90EB2CFEBCE8628DDDF841FBE8B804C4230AC8B69DEAA424E470A290F4AFAC3D713DA85F5513A8AB46F883690E92531EDB5D984429CCBA67EFE3ABB43F7ED3EB4748F58C90986396C893543A1A355C918CA3ADA1E8B8AD3A74104AF9FC97CFBAAABA0A6EA42A97A26EB2E60BBBFD366B58DF9BAAA263EAE5143296F5CE3707D148CCDF4AF0AD0F0B3977FC61958D229BC3C35ECF972F8B619A6AEEC4C7AE1EDE5C06FE4536D4EA26E50D4523A75633C311DA69D79AAF4ABB63C6BF89B65113B682E8A593E287449B6D9";

       
        [TestMethod]
        public void Test1()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SHA1_WITH_RSA_SIGN(Convert.FromBase64String(key), input);
            Assert.IsTrue(Security.SIGN.SHA1_WITH_RSA_VERIFY(Convert.FromBase64String(pub), input, signature));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            Assert.IsTrue(Security.SIGN.SHA1_WITH_RSA_VERIFY(Convert.FromBase64String(pub), input, Convert.FromHexString(sha1_rsa_signature)));
        }

        [TestMethod]
        public void Test3()
        {
            (byte[] key, byte[] pub ) = Security.Utility.RSA_GENKEY();
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SHA1_WITH_RSA_SIGN(key, input);
            Assert.IsTrue(Security.SIGN.SHA1_WITH_RSA_VERIFY(pub, input, signature));
        }

    }
}