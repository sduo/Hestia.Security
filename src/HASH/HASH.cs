using System.Security.Cryptography;

namespace Hestia.Security
{
    public static partial class HASH
    {
        private static byte[] Hash(byte[] input, HashAlgorithm alg)
        {
            return alg.ComputeHash(input);
        }
    }
}
