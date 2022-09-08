using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class MAC
    {
        public static byte[] HMAC_SHA1(byte[] key, byte[] input) => Core.HMAC("HMAC-SHA1",new KeyParameter(key),input);

        public static byte[] HMAC_SHA256(byte[] key, byte[] input) => Core.HMAC("HMAC-SHA256", new KeyParameter(key), input);
    }
}