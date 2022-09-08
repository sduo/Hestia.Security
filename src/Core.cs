using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Hestia.Security
{
    public static partial class Core
    {
        
        public static byte[] Crypto(string alg, bool encrypt, ICipherParameters parameters, byte[] input)
        {
            IBufferedCipher pbc = CipherUtilities.GetCipher(alg);
            pbc.Init(encrypt, parameters);            
            return pbc.DoFinal(input);
        }

        public static byte[] Sign(string alg, ICipherParameters parameters, byte[] input)
        {
            ISigner signer = SignerUtilities.GetSigner(alg);
            signer.Init(true, parameters);
            signer.BlockUpdate(input, 0, input.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(string alg, ICipherParameters parameters, byte[] input, byte[] signature)
        {
            ISigner signer = SignerUtilities.GetSigner(alg);
            signer.Init(false, parameters);
            signer.BlockUpdate(input, 0, input.Length);
            return signer.VerifySignature(signature);
        }


        public static AsymmetricCipherKeyPair GenerateKey(string alg, KeyGenerationParameters parameters)
        {
            IAsymmetricCipherKeyPairGenerator generator = GeneratorUtilities.GetKeyPairGenerator(alg);
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }

        public static byte[] HMAC (string alg, ICipherParameters parameters, byte[] input)
        {
            IMac mac = MacUtilities.GetMac(alg);

            mac.Init(parameters);
            mac.BlockUpdate(input, 0, input.Length);
            
            return MacUtilities.DoFinal(mac);
        }


        public static byte[] Hash(string hash, byte[] input)
        {
            IDigest digest = DigestUtilities.GetDigest(hash);
            digest.BlockUpdate(input, 0, input.Length);
            return DigestUtilities.DoFinal(digest); 
        }
    }
}