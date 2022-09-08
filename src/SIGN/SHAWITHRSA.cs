﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Hestia.Security
{
    public static partial class SIGN
    {
        public static byte[] SHA256_WITH_RSA_SIGN(byte[] key, byte[] input) => Core.Sign("SHA256WITHRSA", PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);

        public static bool SHA256_WITH_RSA_VERIFY(byte[] pub, byte[] input, byte[] signature) => Core.Verify("SHA256WITHRSA", PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input, signature);

        public static byte[] SHA512_WITH_RSA_SIGN(byte[] key, byte[] input) => Core.Sign("SHA512WITHRSA", PrivateKeyFactory.CreateKey(Asn1Object.FromByteArray(key).GetEncoded()), input);

        public static bool SHA512_WITH_RSA_VERIFY(byte[] pub, byte[] input, byte[] signature) => Core.Verify("SHA512WITHRSA", PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(pub))), input, signature);
    }
}