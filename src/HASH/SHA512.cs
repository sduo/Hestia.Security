namespace Hestia.Security
{
    public static partial class HASH
    {
        public static byte[] SHA512(byte[] input) => Hash(input, System.Security.Cryptography.SHA512.Create());
    }
}
