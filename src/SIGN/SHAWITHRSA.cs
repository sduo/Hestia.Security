using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Hestia.Security
{
    public static partial class SIGN
    {
        public static byte[] SHA1_WITH_RSA_SIGN(byte[] key, byte[] input) => SHA1_WITH_RSA_SIGN(PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);

        public static byte[] SHA1_WITH_RSA_SIGN(ICipherParameters key, byte[] input) => Core.Sign("SHA1WITHRSA", key, input);

        public static bool SHA1_WITH_RSA_VERIFY(byte[] pub, byte[] input, byte[] signature) => SHA1_WITH_RSA_VERIFY(PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input, signature);

        public static bool SHA1_WITH_RSA_VERIFY(ICipherParameters pub, byte[] input, byte[] signature) => Core.Verify("SHA1WITHRSA", pub, input, signature);

        public static byte[] SHA256_WITH_RSA_SIGN(byte[] key, byte[] input) => SHA256_WITH_RSA_SIGN(PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);

        public static byte[] SHA256_WITH_RSA_SIGN(ICipherParameters key, byte[] input) => Core.Sign("SHA256WITHRSA", key, input);

        public static bool SHA256_WITH_RSA_VERIFY(byte[] pub, byte[] input, byte[] signature) => SHA256_WITH_RSA_VERIFY(PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))),input,signature);

        public static bool SHA256_WITH_RSA_VERIFY(ICipherParameters pub, byte[] input, byte[] signature) => Core.Verify("SHA256WITHRSA", pub, input, signature);

        public static byte[] SHA512_WITH_RSA_SIGN(byte[] key, byte[] input) => SHA512_WITH_RSA_SIGN(PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);
        
        public static byte[] SHA512_WITH_RSA_SIGN(ICipherParameters key, byte[] input) => Core.Sign("SHA512WITHRSA", key, input);

        public static bool SHA512_WITH_RSA_VERIFY(byte[] pub, byte[] input, byte[] signature) => SHA512_WITH_RSA_VERIFY(PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input, signature);

        public static bool SHA512_WITH_RSA_VERIFY(ICipherParameters pub, byte[] input, byte[] signature) => Core.Verify("SHA512WITHRSA", pub, input, signature);
    }
}