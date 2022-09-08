using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        public static byte[] AES_CBC_PKCS7PADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_PKCS7PADDING(false, key, iv, input);

        public static byte[] AES_CBC_PKCS7PADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_PKCS7PADDING(true, key, iv, input);

        private static byte[] AES_CBC_PKCS7PADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("AES/CBC/PKCS7PADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        public static byte[] AES_CBC_ZEROBYTEPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_ZEROBYTEPADDING(false, key, iv, input);

        public static byte[] AES_CBC_ZEROBYTEPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_ZEROBYTEPADDING(true, key, iv, input);

        private static byte[] AES_CBC_ZEROBYTEPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("AES/CBC/ZEROBYTEPADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        public static byte[] AES_CBC_NOPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_NOPADDING(false, key, iv, input);

        public static byte[] AES_CBC_NOPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_CBC_NOPADDING(true, key, iv, input);

        private static byte[] AES_CBC_NOPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("AES/CBC/NOPADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        public static byte[] AES_GCM_NOPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES_GCM_NOPADDING(false, key, iv, input);

        public static byte[] AES_GCM_NOPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES_GCM_NOPADDING(true, key, iv, input);

        private static byte[] AES_GCM_NOPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("AES/GCM/NOPADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);
    }
}