namespace Hestia.Security
{
    public static partial class HASH
    {
        public static byte[] SHA384(byte[] input) => Hash(input, System.Security.Cryptography.SHA384.Create());
    }
}
