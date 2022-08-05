using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security
{
    public static partial class Core
    {
        
        public static byte[] Crypto(string alg, bool encrypt, byte[] key, byte[] iv, byte[] input)
        {
            IBufferedCipher pbc = CipherUtilities.GetCipher(alg);
            KeyParameter kp = new(key);
            ParametersWithIV parameters = new(kp, iv);
            pbc.Init(encrypt, parameters);
            return pbc.DoFinal(input);
        }

        public static byte[] Hash(string hash, byte[] input)
        {
            var alg = HashAlgorithm.Create(hash);
            return alg.ComputeHash(input);
        }
    }
}
