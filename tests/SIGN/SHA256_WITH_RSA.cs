using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Cmp;
using System.Security.Cryptography;

namespace Hestia.Security.Tests.SIGN
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class SHA256_WITH_RSA
    {
        private const string source = "Hestia.Security";
        private const string pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkFuJsqGjmof5r1pMImfNNEhDg6qGiXhm6Noo5dlMkWhRdR6kkrlsLIJQQKOtDLT/3JI328LFH1CNmhAoo2K94L7x0SpMVdYrCRsz7Ue97jQqwd6mAyD2vegNhnUV+akubuvC5u8SNKMA7bRw/TRl/kA692Cbmr9SuOdnVclfjYyfN+r0YeUfSxSMnVm6LNbZLwfcWq75iatCaNoSn4p9/F4x7/+S96XiDqVP5qrRBBdoew1yHFfVqQQOB7Ovf5QSc9rpsFbChIp11k7xVm0rKfBxrmtImU5Rx5kM/0L9xtO134fqlt/+XzXg9jAtHyqUEPBIdRjIzQk3t3NI2pqaNwIDAQAB";
        private const string key = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCQW4myoaOah/mvWkwiZ800SEODqoaJeGbo2ijl2UyRaFF1HqSSuWwsglBAo60MtP/ckjfbwsUfUI2aECijYr3gvvHRKkxV1isJGzPtR73uNCrB3qYDIPa96A2GdRX5qS5u68Lm7xI0owDttHD9NGX+QDr3YJuav1K452dVyV+NjJ836vRh5R9LFIydWbos1tkvB9xarvmJq0Jo2hKfin38XjHv/5L3peIOpU/mqtEEF2h7DXIcV9WpBA4Hs69/lBJz2umwVsKEinXWTvFWbSsp8HGua0iZTlHHmQz/Qv3G07Xfh+qW3/5fNeD2MC0fKpQQ8Eh1GMjNCTe3c0jampo3AgMBAAECggEABhjXqAPLtSspEI7vyEQ6Fos2zsjVBdlf/1W3hH25DispxZiVuty6BOc8HH7NQEwkwlwqn82KJdhxIqCsFrqE6okmDX+L2dRB3RCZENyG2Ri69ZVBzcAGq96xM4yecP0ESQsMIFTYoACCeYe1ffxIkoSD+Q7Lg62xAL5FTwpCTughSkBaihDX9sA019ZupTDrK8utblk5dD6ivKYQEJE02EcwjIIrLZNQdNBnQDsOubuJIes1b+QQwiKxNN2D6nNTzjO63v97J6mDA49nzlcBac/Un6rXRsQvYGOsB2n+RL6Fwki0X02i7sK/jbE8An5TtIpECH1jowz+O+GDcC9JAQKBgQDODdVx/15uTxbXHs4IM8d1no4PwTDBok5N8k/k6BA8+TM46e6dWTVKnGm4BRkzt3DaguoDHa+cYGXr822NYFb6sZHMGKgLlpwByc5GjCsgTCFA11pOpyuna9ZULyjk2n1oqt+QZD1pvlvNH9rMbvWmNA+uzB19+qU1jYaYJulnDwKBgQCzWUjbr+awSC7y5pEDw9QqKEIxxsAWGmglu0ZpxihduwakVbjxNAkwlyXCvFxwdp1pNeMfils3OvsMqdlMTHELx4H8yQmFb7gxuuQ9fuZR0dsscn3WSGG6NnwGNyD4fCvljBson/PC1Zkfonf+rcVfijKspGknREZLVNx5yx3aWQKBgFxClW+ViBKcFv37LQU/Ke/gLnufZNVOdwEvndZAkgS7D9RL6itJ5jKiFjPvFHmziTRNqbn7cMXz467iMAs9N7TIDR/1akjGBtRGJ7YuzKCJddoykpzk/QbZof3Pn9/YdI6I89ETEOxn73LI8I7Yn+TrKpp5ijr+Hzr7Q2idA6TBAoGANngnaJFDvsYtfBgKctpG1Ybkk7mJHS1n9A2slPNZzx2+JqriQF9NazR8g2gxqvZbWFjFYg7jJSMEnBP5qvKMYsd08xEbkysbBf980jB4QuE5b4ZWMX5KMAPcJwcXPGB59H1Ywj3SCppUpwbw6qhcCWgve79zMDnMH5TmYRcPOgECgYB8TjIHiYha4CZa98OC9FH9IkPczOn8xZMPuFZYnirmbIOw4LjqimQicYCse1NQ5SoWrCUMOwBE8tnEtw6fMWO/keKl0JRDIP/RzfJTZvg+AHtN2/GruVi8loX4DkHAg3u5wC3a/fDDWKj7x0E1KOlsb11xeIisqHXR6PFyHHcx9Q==";
        private const string sha256_rsa_signature = "21325F05CCAC2FE9444F3BF4DE570639592DC75F0D3CDC71D84CBBE1A17B808902CD17AF1B5968068371E67A416B5B7C5CF35609A8A13A024FA94E72A30AD3F3AB846689F3A3CD752DC1B22E1538FEDFC5CA183D6EF8FBB19F00F8EF1EC329548483DAB29B8372490632BD60F9CC549B1B934C0DA9561F4731B4FFA960FB12AB7FC2A10129E22D703CEEE0DA3A8E8AC26867B9D36504DAAB3BD3924055C5CEA680A5D3CDCD0A7471636B6AE9365423791DAEFE1C29E890E5992A83EAFDBC43334A49FD570F791E4048B789ADAC9CA44D398BB71B49C82A068408B964D05941323C75027ECA28692BBE7F02D7D2BFC31C7DC2A5B5021E239D1CC4481DF53FE9C4";

        // https://help.aliyun.com/document_detail/177489.html
        private const string aliyun_api_jwt_header = "{\"alg\":\"RS256\",\"kid\":\"uniq_key\"}";
        private const string aliyun_api_jwt_playload = "{\"jid\":\"y5iKBpHwZTMeHF1QhKts8A\",\"iat\":\"1662929808\",\"nfb\":\"1662929808\",\"exp\":\"1662933408\",\"sub\":\"YOUR_SUBJECT\",\"aud\":\"YOUR_AUDIENCE\",\"userId\":\"1213234\",\"email\":\"userEmail@youapp.com\"}";
        private const string aliyun_api_jwt_key = "{\"kty\": \"RSA\",\"d\":\"O9MJSOgcjjiVMNJ4jmBAh0mRHF_TlaVva70Imghtlgwxl8BLfcf1S8ueN1PD7xV6Cnq8YenSKsfiNOhC6yZ_fjW1syn5raWfj68eR7cjHWjLOvKjwVY33GBPNOvspNhVAFzeqfWneRTBbga53Agb6jjN0SUcZdJgnelzz5JNdOGaLzhacjH6YPJKpbuzCQYPkWtoZHDqWTzCSb4mJ3n0NRTsWy7Pm8LwG_Fd3pACl7JIY38IanPQDLoighFfo-Lriv5z3IdlhwbPnx0tk9sBwQBTRdZ8JkqqYkxUiB06phwr7mAnKEpQJ6HvhZBQ1cCnYZ_nIlrX9-I7qomrlE1UoQ\",\"e\": \"AQAB\",\"kid\": \"myJwtKey\",\"alg\": \"RS256\",\"n\": \"vCuB8MgwPZfziMSytEbBoOEwxsG7XI3MaVMoocziP4SjzU4IuWuE_DodbOHQwb_thUru57_Efe--sfATHEa0Odv5ny3QbByqsvjyeHk6ZE4mSAV9BsHYa6GWAgEZtnDceeeDc0y76utXK2XHhC1Pysi2KG8KAzqDa099Yh7s31AyoueoMnrYTmWfEyDsQL_OAIiwgXakkS5U8QyXmWicCwXntDzkIMh8MjfPskesyli0XQD1AmCXVV3h2Opm1Amx0ggSOOiINUR5YRD6mKo49_cN-nrJWjtwSouqDdxHYP-4c7epuTcdS6kQHiQERBd1ejdpAxV4c0t0FHF7MOy9kw\"}";
        private const string aliyun_api_jwt_signature = "A03z1-Rh1I7Ar04ajJB5m3JSAkM_r8-aLMx3OUAQnryYq9T51XDk9UA1atbvkfCFVzq8v77b1VWHtU8aY8b0Mp5-CCxd1-gBRwqLDwose5fe0OB2E2ST559IFIeE0lAXBdOTFpl2rH_R7gDMDMLIBdxjXL3kq9tIqCWiJvYy0YC_RozuH3DntUYTPMXfKsUev5Ktug4lGtf4wRmDB_ZEzlIGPtpQDSW-wpJHwjGAWVjXv_AVzZfDTSXFHCNa9tqaxxMuiamdvLK8LBYx75dMoxPXt-RfeMNFU_fWFUKd-HNLK6ELMUbmssE75Eqnh9HosARt9WXXGX6zvVJ4TO-swg";

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
            JsonWebKey jwk = JsonWebKey.Create(aliyun_api_jwt_key);
            BigInteger n = new (1, Base64UrlEncoder.DecodeBytes(jwk.N));
            BigInteger d = new(1, Base64UrlEncoder.DecodeBytes(jwk.D));
            RsaKeyParameters key = new(true, n, d);
            string source = Security.Utility.Concat(".", Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(aliyun_api_jwt_header)), Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(aliyun_api_jwt_playload)));
            byte[] output = Security.SIGN.SHA256_WITH_RSA_SIGN(key, Encoding.UTF8.GetBytes(source));
            Assert.AreEqual(aliyun_api_jwt_signature, Base64UrlEncoder.Encode(output));
        }

        [TestMethod]
        public void Test5()
        {
            JsonWebKey jwk = JsonWebKey.Create(aliyun_api_jwt_key);
            BigInteger n = new(1, Base64UrlEncoder.DecodeBytes(jwk.N));
            BigInteger e = new(1, Base64UrlEncoder.DecodeBytes(jwk.E));
            RsaKeyParameters pub = new(false, n, e);
            string source = Security.Utility.Concat(".", Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(aliyun_api_jwt_header)), Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(aliyun_api_jwt_playload)));
            Assert.IsTrue( Security.SIGN.SHA256_WITH_RSA_VERIFY(pub, Encoding.UTF8.GetBytes(source), Base64UrlEncoder.DecodeBytes(aliyun_api_jwt_signature)));
        }
    }
}