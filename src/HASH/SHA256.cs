namespace Hestia.Security
{
    public static partial class HASH
    {
        public static byte[] SHA256(byte[] input) => Hash(input, System.Security.Cryptography.SHA256.Create());
    }
}
