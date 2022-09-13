using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        public static byte[] SM2_ENCRYPT(byte[] pub, byte[] input) => SM2_ENCRYPT(pub, input, new SM3Digest());
        public static byte[] SM2_ENCRYPT(ICipherParameters pub, byte[] input) => SM2_ENCRYPT(pub, input, new SM3Digest());
        public static byte[] SM2_ENCRYPT(byte[] pub, byte[] input, IDigest digest) => SM2_ENCRYPT(pub, input, new SecureRandom(), digest);
        public static byte[] SM2_ENCRYPT(byte[] pub, byte[] input, SecureRandom random, IDigest digest) => SM2_ENCRYPT(new ParametersWithRandom(new ECPublicKeyParameters(Utility.SM2P256V1.Curve.DecodePoint(pub), Utility.SM2P256V1_DOMAIN), random), input, digest);
        public static byte[] SM2_ENCRYPT(ICipherParameters pub, byte[] input, IDigest digest) => SM2(true, pub, digest, input);
        public static byte[] SM2_DECRYPT(byte[] key, byte[] input) => SM2_DECRYPT(key, input,new SM3Digest());
        public static byte[] SM2_DECRYPT(ICipherParameters key, byte[] input) => SM2_DECRYPT(key, input, new SM3Digest());
        public static byte[] SM2_DECRYPT(byte[] key, byte[] input, IDigest digest) => SM2_DECRYPT(new ECPrivateKeyParameters(new BigInteger(key), Utility.SM2P256V1_DOMAIN), input, digest);
        public static byte[] SM2_DECRYPT(ICipherParameters key, byte[] input, IDigest digest) => SM2(false, key, digest, input);
        private static byte[] SM2(bool encrypt, ICipherParameters key,IDigest digest, byte[] input)
        {            
            SM2Engine engine =new(digest);
            engine.Init(encrypt, key);
            return engine.ProcessBlock(input,0,input.Length);         
        }
    }
}