﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Hestia.Security
{
    public static partial class SIGN
    {
        public static byte[] SM3_WITH_SM2_SIGN(byte[] key, byte[] input) => SM3_WITH_SM2_SIGN(key, input, Utility.DEFAULT_SM2_ID);

        public static byte[] SM3_WITH_SM2_SIGN(byte[] key, byte[] input, byte[] id) => SM3_WITH_SM2_SIGN(new ParametersWithID(new ECPrivateKeyParameters(new BigInteger(key), Utility.SM2P256V1_DOMAIN), id), input);

        public static byte[] SM3_WITH_SM2_SIGN(ICipherParameters key, byte[] input) => Core.Sign("SM3WITHSM2", key, input);

        public static bool SM3_WITH_SM2_VERIFY(byte[] pub, byte[] input, byte[] signature) => SM3_WITH_SM2_VERIFY(new ECPublicKeyParameters(Utility.SM2P256V1.Curve.DecodePoint(pub), Utility.SM2P256V1_DOMAIN), input, signature);

        public static bool SM3_WITH_SM2_VERIFY(ICipherParameters pub, byte[] input, byte[] signature) => Core.Verify("SM3WITHSM2", pub, input, signature);
    }
}