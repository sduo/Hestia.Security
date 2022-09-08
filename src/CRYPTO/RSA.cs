using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {

        public static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING_ENCRYPT(byte[] key, byte[] input) => RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(true, PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);

        public static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING_DECRYPT(byte[] pub, byte[] input) => RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(false, PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input);

        private static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(bool encrypt, AsymmetricKeyParameter parameter, byte[] input) => Core.Crypto("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", encrypt, parameter, input);
    }
}