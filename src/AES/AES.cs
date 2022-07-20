using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Hestia.Security
{
    public static partial class AES
    {
        private static byte[] AES128_CBC(bool encrypt, byte[] key, byte[] iv, byte[] input, IBlockCipherPadding padding)
        {
            AesEngine engine = new();
            CbcBlockCipher bc = new(engine);
            PaddedBufferedBlockCipher pbc = new(bc, padding);
            KeyParameter kp = new(key);
            ParametersWithIV parameters = new(kp, iv);
            pbc.Init(encrypt, parameters);
            return pbc.DoFinal(input);
        }
    }
}
