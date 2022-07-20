namespace Hestia.Security
{
    public static partial class HASH
    {
        public static byte[] SHA1(byte[] input) => Hash(input, System.Security.Cryptography.SHA1.Create());
    }
}
