using Org.BouncyCastle.Crypto.Paddings;

namespace Hestia.Security
{
    public static partial class AES
    {
        public static byte[] AES128_CBC_ZERO_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES128_CBC_ZERO(false, key, iv, input);

        public static byte[] AES128_CBC_ZERO_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES128_CBC_ZERO(true, key, iv, input);

        private static byte[] AES128_CBC_ZERO(bool encrypt, byte[] key, byte[] iv, byte[] input) => AES128_CBC(encrypt, key, iv, input, new ZeroBytePadding());
    }
}
