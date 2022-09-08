namespace Hestia.Security
{
    public static partial class HASH
    {
        public static byte[] MD5(byte[] input) => Core.Hash("MD5", input);
        public static byte[] SHA1(byte[] input) => Core.Hash("SHA1", input);
        public static byte[] SHA256(byte[] input) => Core.Hash("SHA256", input);
        public static byte[] SHA384(byte[] input) => Core.Hash("SHA384", input);
        public static byte[] SHA512(byte[] input) => Core.Hash("SHA512", input);
        public static byte[] SM3(byte[] input) => Core.Hash("SM3", input);
    }
}
