using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Hestia.Security.Tests.SIGN
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA_WITH_RSA
    {
        private const string source = "Hestia.Security";
        private const string pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkFuJsqGjmof5r1pMImfNNEhDg6qGiXhm6Noo5dlMkWhRdR6kkrlsLIJQQKOtDLT/3JI328LFH1CNmhAoo2K94L7x0SpMVdYrCRsz7Ue97jQqwd6mAyD2vegNhnUV+akubuvC5u8SNKMA7bRw/TRl/kA692Cbmr9SuOdnVclfjYyfN+r0YeUfSxSMnVm6LNbZLwfcWq75iatCaNoSn4p9/F4x7/+S96XiDqVP5qrRBBdoew1yHFfVqQQOB7Ovf5QSc9rpsFbChIp11k7xVm0rKfBxrmtImU5Rx5kM/0L9xtO134fqlt/+XzXg9jAtHyqUEPBIdRjIzQk3t3NI2pqaNwIDAQAB";
        private const string key = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCQW4myoaOah/mvWkwiZ800SEODqoaJeGbo2ijl2UyRaFF1HqSSuWwsglBAo60MtP/ckjfbwsUfUI2aECijYr3gvvHRKkxV1isJGzPtR73uNCrB3qYDIPa96A2GdRX5qS5u68Lm7xI0owDttHD9NGX+QDr3YJuav1K452dVyV+NjJ836vRh5R9LFIydWbos1tkvB9xarvmJq0Jo2hKfin38XjHv/5L3peIOpU/mqtEEF2h7DXIcV9WpBA4Hs69/lBJz2umwVsKEinXWTvFWbSsp8HGua0iZTlHHmQz/Qv3G07Xfh+qW3/5fNeD2MC0fKpQQ8Eh1GMjNCTe3c0jampo3AgMBAAECggEABhjXqAPLtSspEI7vyEQ6Fos2zsjVBdlf/1W3hH25DispxZiVuty6BOc8HH7NQEwkwlwqn82KJdhxIqCsFrqE6okmDX+L2dRB3RCZENyG2Ri69ZVBzcAGq96xM4yecP0ESQsMIFTYoACCeYe1ffxIkoSD+Q7Lg62xAL5FTwpCTughSkBaihDX9sA019ZupTDrK8utblk5dD6ivKYQEJE02EcwjIIrLZNQdNBnQDsOubuJIes1b+QQwiKxNN2D6nNTzjO63v97J6mDA49nzlcBac/Un6rXRsQvYGOsB2n+RL6Fwki0X02i7sK/jbE8An5TtIpECH1jowz+O+GDcC9JAQKBgQDODdVx/15uTxbXHs4IM8d1no4PwTDBok5N8k/k6BA8+TM46e6dWTVKnGm4BRkzt3DaguoDHa+cYGXr822NYFb6sZHMGKgLlpwByc5GjCsgTCFA11pOpyuna9ZULyjk2n1oqt+QZD1pvlvNH9rMbvWmNA+uzB19+qU1jYaYJulnDwKBgQCzWUjbr+awSC7y5pEDw9QqKEIxxsAWGmglu0ZpxihduwakVbjxNAkwlyXCvFxwdp1pNeMfils3OvsMqdlMTHELx4H8yQmFb7gxuuQ9fuZR0dsscn3WSGG6NnwGNyD4fCvljBson/PC1Zkfonf+rcVfijKspGknREZLVNx5yx3aWQKBgFxClW+ViBKcFv37LQU/Ke/gLnufZNVOdwEvndZAkgS7D9RL6itJ5jKiFjPvFHmziTRNqbn7cMXz467iMAs9N7TIDR/1akjGBtRGJ7YuzKCJddoykpzk/QbZof3Pn9/YdI6I89ETEOxn73LI8I7Yn+TrKpp5ijr+Hzr7Q2idA6TBAoGANngnaJFDvsYtfBgKctpG1Ybkk7mJHS1n9A2slPNZzx2+JqriQF9NazR8g2gxqvZbWFjFYg7jJSMEnBP5qvKMYsd08xEbkysbBf980jB4QuE5b4ZWMX5KMAPcJwcXPGB59H1Ywj3SCppUpwbw6qhcCWgve79zMDnMH5TmYRcPOgECgYB8TjIHiYha4CZa98OC9FH9IkPczOn8xZMPuFZYnirmbIOw4LjqimQicYCse1NQ5SoWrCUMOwBE8tnEtw6fMWO/keKl0JRDIP/RzfJTZvg+AHtN2/GruVi8loX4DkHAg3u5wC3a/fDDWKj7x0E1KOlsb11xeIisqHXR6PFyHHcx9Q==";
        private const string sha256_rsa_signature = "21325F05CCAC2FE9444F3BF4DE570639592DC75F0D3CDC71D84CBBE1A17B808902CD17AF1B5968068371E67A416B5B7C5CF35609A8A13A024FA94E72A30AD3F3AB846689F3A3CD752DC1B22E1538FEDFC5CA183D6EF8FBB19F00F8EF1EC329548483DAB29B8372490632BD60F9CC549B1B934C0DA9561F4731B4FFA960FB12AB7FC2A10129E22D703CEEE0DA3A8E8AC26867B9D36504DAAB3BD3924055C5CEA680A5D3CDCD0A7471636B6AE9365423791DAEFE1C29E890E5992A83EAFDBC43334A49FD570F791E4048B789ADAC9CA44D398BB71B49C82A068408B964D05941323C75027ECA28692BBE7F02D7D2BFC31C7DC2A5B5021E239D1CC4481DF53FE9C4";
        private const string sha512_rsa_signature = "551FC0A0DBA39FD678640D7B9D9D150FCE4191C4D299AB02086DD746026D7587AC01B25FFE368780C9E77E165C6D806A92671C35F2C81EA7659AFFF349AC0C362A644F0329EBE4E67086C3B4AB33B8A104B846DC85AFBC72EA26837A4DD0102EE826DCCE7CF98C3B1FF27F6E511A02AD7810214B5ABCD84115F1AE1BEDA51C5F9336B050C816FF29F17DDAF37887F93DB0D697FB2173968FFA6927DE7D267DC26A97F045E7743280323C6359451631652DBF3997F83CBAE906ACE868D62FDF6163C54AB28C9145229738825DB6CE5E15B88959E054481CE24508DEC94CF1F32576158F2986E679D054CC1ACB3DC90AB46786BC31ED4F7AE083C33B25350B38AC";

        [TestMethod]
        public void Test1()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SHA256_WITH_RSA_SIGN(Convert.FromBase64String(key), input);
            Assert.IsTrue(Security.SIGN.SHA256_WITH_RSA_VERIFY(Convert.FromBase64String(pub), input, signature));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            Assert.IsTrue(Security.SIGN.SHA256_WITH_RSA_VERIFY(Convert.FromBase64String(pub), input, Convert.FromHexString(sha256_rsa_signature)));
        }

        [TestMethod]
        public void Test3()
        {
            (byte[] key, byte[] pub ) = Security.Utility.RSA_GENKEY();
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SHA256_WITH_RSA_SIGN(key, input);
            Assert.IsTrue(Security.SIGN.SHA256_WITH_RSA_VERIFY(pub, input, signature));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SHA512_WITH_RSA_SIGN(Convert.FromBase64String(key), input);
            Assert.IsTrue(Security.SIGN.SHA512_WITH_RSA_VERIFY(Convert.FromBase64String(pub), input, signature));
        }

        [TestMethod]
        public void Test5()
        {
            byte[] input = Encoding.UTF8.GetBytes(source);
            Assert.IsTrue(Security.SIGN.SHA512_WITH_RSA_VERIFY(Convert.FromBase64String(pub), input, Convert.FromHexString(sha512_rsa_signature)));
        }

        [TestMethod]
        public void Test6()
        {
            (byte[] key, byte[] pub) = Security.Utility.RSA_GENKEY();
            byte[] input = Encoding.UTF8.GetBytes(source);
            byte[] signature = Security.SIGN.SHA512_WITH_RSA_SIGN(key, input);
            Assert.IsTrue(Security.SIGN.SHA512_WITH_RSA_VERIFY(pub, input, signature));
        }
    }
}