using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        #region SM4_CBC_PKCS7PADDING       
        public static byte[] SM4_CBC_PKCS7PADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_PKCS7PADDING(false, key, iv, input);
        public static byte[] SM4_CBC_PKCS7PADDING_DECRYPT(ICipherParameters key, byte[] input) => SM4_CBC_PKCS7PADDING(false, key, input);

        public static byte[] SM4_CBC_PKCS7PADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_PKCS7PADDING(true, key, iv, input);
        public static byte[] SM4_CBC_PKCS7PADDING_ENCRYPT(ICipherParameters key, byte[] input) => SM4_CBC_PKCS7PADDING(true, key, input);

        private static byte[] SM4_CBC_PKCS7PADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => SM4_CBC_PKCS7PADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] SM4_CBC_PKCS7PADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("SM4/CBC/PKCS7PADDING", encrypt, key, input);

        #endregion

        #region SM4_CBC_ZEROBYTEPADDING
        public static byte[] SM4_CBC_ZEROBYTEPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_ZEROBYTEPADDING(false, key, iv, input);
        public static byte[] SM4_CBC_ZEROBYTEPADDING_DECRYPT(ICipherParameters key, byte[] input) => SM4_CBC_ZEROBYTEPADDING(false, key, input);

        public static byte[] SM4_CBC_ZEROBYTEPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_ZEROBYTEPADDING(true, key, iv, input);
        public static byte[] SM4_CBC_ZEROBYTEPADDING_ENCRYPT(ICipherParameters key, byte[] input) => SM4_CBC_ZEROBYTEPADDING(true, key, input);

        private static byte[] SM4_CBC_ZEROBYTEPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => SM4_CBC_ZEROBYTEPADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] SM4_CBC_ZEROBYTEPADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("SM4/CBC/ZEROBYTEPADDING", encrypt, key, input);
        #endregion

        #region SM4_CBC_NOPADDING
        public static byte[] SM4_CBC_NOPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_NOPADDING(false, key, iv, input);

        public static byte[] SM4_CBC_NOPADDING_DECRYPT(ICipherParameters key, byte[] input) => SM4_CBC_NOPADDING(false, key,  input);

        public static byte[] SM4_CBC_NOPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_NOPADDING(true, key, iv, input);

        public static byte[] SM4_CBC_NOPADDING_ENCRYPT(ICipherParameters key, byte[] input) => SM4_CBC_NOPADDING(true, key, input);

        private static byte[] SM4_CBC_NOPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => SM4_CBC_NOPADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] SM4_CBC_NOPADDING(bool encrypt, ICipherParameters key,  byte[] input) => Core.Crypto("SM4/CBC/NOPADDING", encrypt, key, input);

        #endregion
    }
}