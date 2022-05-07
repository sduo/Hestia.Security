using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class Utility
    {
        public static byte[] AES128_CBC_PKCS7_DECRYPT(byte[] key, byte[] iv, byte[] input) => AES128_CBC_PKCS7(false, key, iv, input);

        public static byte[] AES128_CBC_PKCS7_ENCRYPT(byte[] key, byte[] iv, byte[] input) => AES128_CBC_PKCS7(true, key, iv, input);

        private static byte[] AES128_CBC_PKCS7(bool encrypt, byte[] key, byte[] iv, byte[] input)
        {
            AesEngine engine = new();
            CbcBlockCipher bc = new(engine);
            PaddedBufferedBlockCipher pbc = new(bc, new Pkcs7Padding());
            KeyParameter kp = new(key);
            ParametersWithIV parameters = new(kp, iv);
            pbc.Init(encrypt, parameters);
            return pbc.DoFinal(input);
        }
    }
}