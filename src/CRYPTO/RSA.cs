using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        #region RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING
        public static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING_ENCRYPT(byte[] key, byte[] input) => RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(true, PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);
        public static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING_ENCRYPT(ICipherParameters key, byte[] input) => RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(true, key, input);
        public static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING_DECRYPT(byte[] pub, byte[] input) => RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(false, PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input);
        public static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING_DECRYPT(ICipherParameters pub, byte[] input) => RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(false, pub, input);
        private static byte[] RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", encrypt, key, input);
        #endregion

        #region RSA_ECB_PKCS1PADDING
        public static byte[] RSA_ECB_PKCS1PADDING_ENCRYPT(byte[] key, byte[] input) => RSA_ECB_PKCS1PADDING(true, PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);
        public static byte[] RSA_ECB_PKCS1PADDING_ENCRYPT(ICipherParameters key, byte[] input) => RSA_ECB_PKCS1PADDING(true, key, input);
        public static byte[] RSA_ECB_PKCS1PADDING_DECRYPT(byte[] pub, byte[] input) => RSA_ECB_PKCS1PADDING(false, PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input);
        public static byte[] RSA_ECB_PKCS1PADDING_DECRYPT(ICipherParameters pub, byte[] input) => RSA_ECB_PKCS1PADDING(false, pub, input);
        private static byte[] RSA_ECB_PKCS1PADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("RSA/ECB/PKCS1Padding", encrypt, key, input);
        #endregion
    }
}