namespace Hestia.Security
{
    public static partial class HASH
    {
        public static byte[] MD5(byte[] input) => Hash(input, System.Security.Cryptography.MD5.Create());
    }
}
