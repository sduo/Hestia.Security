using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class MAC
    {
        public static byte[] HMAC_SHA1(byte[] key, byte[] input) => HMAC_SHA1(new KeyParameter(key),input);
        public static byte[] HMAC_SHA1(ICipherParameters key, byte[] input) => Core.HMAC("HMAC-SHA1", key, input);

        public static byte[] HMAC_SHA256(byte[] key, byte[] input) => HMAC_SHA256(new KeyParameter(key), input);

        public static byte[] HMAC_SHA256(ICipherParameters key, byte[] input) => Core.HMAC("HMAC-SHA256", key, input);
    }
}