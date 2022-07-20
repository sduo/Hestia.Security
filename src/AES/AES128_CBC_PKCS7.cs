using Org.BouncyCastle.Crypto.Paddings;

namespace Hestia.Security
{
    public static partial class AES
    {
        public static byte[] AES128_CBC_PKCS7_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES128_CBC_PKCS7(false, key, iv, input);

        public static byte[] AES128_CBC_PKCS7_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES128_CBC_PKCS7(true, key, iv, input);       

        private static byte[] AES128_CBC_PKCS7(bool encrypt, byte[] key, byte[] iv, byte[] input) => AES128_CBC(encrypt, key, iv, input, new Pkcs7Padding());        
    }
}