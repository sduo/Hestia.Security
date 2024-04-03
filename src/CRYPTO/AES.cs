using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        #region AES_CBC_PKCS7PADDING
        public static byte[] AES_CBC_PKCS7PADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_PKCS7PADDING(false, key, iv, input);

        public static byte[] AES_CBC_PKCS7PADDING_DECRYPT(ICipherParameters key, byte[] input) => AES_CBC_PKCS7PADDING(false, key, input);

        public static byte[] AES_CBC_PKCS7PADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_PKCS7PADDING(true, key, iv, input);

        public static byte[] AES_CBC_PKCS7PADDING_ENCRYPT(ICipherParameters key, byte[] input) => AES_CBC_PKCS7PADDING(true, key, input);

        private static byte[] AES_CBC_PKCS7PADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => AES_CBC_PKCS7PADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] AES_CBC_PKCS7PADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("AES/CBC/PKCS7PADDING", encrypt, key, input);
        #endregion

        #region AES_CBC_ZEROBYTEPADDING
        public static byte[] AES_CBC_ZEROBYTEPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_ZEROBYTEPADDING(false, key, iv, input);

        public static byte[] AES_CBC_ZEROBYTEPADDING_DECRYPT(ICipherParameters key, byte[] input) => AES_CBC_ZEROBYTEPADDING(false, key, input);

        public static byte[] AES_CBC_ZEROBYTEPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_ZEROBYTEPADDING(true, key, iv, input);

        public static byte[] AES_CBC_ZEROBYTEPADDING_ENCRYPT(ICipherParameters key, byte[] input) => AES_CBC_ZEROBYTEPADDING(true, key, input);

        private static byte[] AES_CBC_ZEROBYTEPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => AES_CBC_ZEROBYTEPADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] AES_CBC_ZEROBYTEPADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("AES/CBC/ZEROBYTEPADDING", encrypt, key, input);
        #endregion

        #region AES_CBC_NOPADDING
        public static byte[] AES_CBC_NOPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_NOPADDING(false, key, iv, input);

        public static byte[] AES_CBC_NOPADDING_DECRYPT(ICipherParameters key, byte[] input) => AES_CBC_NOPADDING(false, key, input);

        public static byte[] AES_CBC_NOPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_NOPADDING(true, key, iv, input);

        public static byte[] AES_CBC_NOPADDING_ENCRYPT(ICipherParameters key, byte[] input) => AES_CBC_NOPADDING(true, key, input);

        private static byte[] AES_CBC_NOPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => AES_CBC_NOPADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] AES_CBC_NOPADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("AES/CBC/NOPADDING", encrypt, key, input);

        #endregion

        #region AES_GCM_NOPADDING
        public static byte[] AES_GCM_NOPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_GCM_NOPADDING(false, key, iv, input);

        public static byte[] AES_GCM_NOPADDING_DECRYPT(ICipherParameters key, byte[] input) => AES_GCM_NOPADDING(false, key, input);

        public static byte[] AES_GCM_NOPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_GCM_NOPADDING(true, key, iv, input);

        public static byte[] AES_GCM_NOPADDING_ENCRYPT(ICipherParameters key, byte[] input) => AES_GCM_NOPADDING(true, key, input);

        private static byte[] AES_GCM_NOPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => AES_GCM_NOPADDING(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        private static byte[] AES_GCM_NOPADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("AES/GCM/NOPADDING", encrypt, key, input);

        #endregion

        #region AES/ECB/PKCS5Padding
        public static byte[] AES_ECB_PKCS5PADDING_DECRYPT(byte[] key, byte[] input) => AES_ECB_PKCS5PADDING(false, key,input);

        public static byte[] AES_ECB_PKCS5PADDING_DECRYPT(ICipherParameters key, byte[] input) => AES_ECB_PKCS5PADDING(false, key, input);

        public static byte[] AES_ECB_PKCS5PADDING_ENCRYPT(byte[] key, byte[] input) => AES_ECB_PKCS5PADDING(true, key,input);

        public static byte[] AES_ECB_PKCS5PADDING_ENCRYPT(ICipherParameters key, byte[] input) => AES_ECB_PKCS5PADDING(true, key, input);

        private static byte[] AES_ECB_PKCS5PADDING(bool encrypt, byte[] key, byte[] input) => AES_ECB_PKCS5PADDING(encrypt, new KeyParameter(key), input);

        private static byte[] AES_ECB_PKCS5PADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("AES/ECB/PKCS5Padding", encrypt, key, input);

        #endregion

        #region AES/ECB/PKCS7Padding
        public static byte[] AES_ECB_PKCS7PADDING_DECRYPT(byte[] key, byte[] input) => AES_ECB_PKCS7PADDING(false, key, input);

        public static byte[] AES_ECB_PKCS7PADDING_DECRYPT(ICipherParameters key, byte[] input) => AES_ECB_PKCS7PADDING(false, key, input);

        public static byte[] AES_ECB_PKCS7PADDING_ENCRYPT(byte[] key, byte[] input) => AES_ECB_PKCS7PADDING(true, key, input);

        public static byte[] AES_ECB_PKCS7PADDING_ENCRYPT(ICipherParameters key, byte[] input) => AES_ECB_PKCS7PADDING(true, key, input);

        private static byte[] AES_ECB_PKCS7PADDING(bool encrypt, byte[] key, byte[] input) => AES_ECB_PKCS7PADDING(encrypt, new KeyParameter(key), input);

        private static byte[] AES_ECB_PKCS7PADDING(bool encrypt, ICipherParameters key, byte[] input) => Core.Crypto("AES/ECB/PKCS7Padding", encrypt, key, input);

        #endregion
    }
}