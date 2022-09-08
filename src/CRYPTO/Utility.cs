using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;

namespace Hestia.Security
{
    public static partial class Utility
    {

        public static readonly byte[] DEFAULT_RSA_PUBLIC_EXPONENT = new byte[] { 0x01, 0x00, 0x01 };
        public readonly static X9ECParameters SM2P256V1 = GMNamedCurves.GetByName("SM2P256V1");
        public readonly static ECDomainParameters SM2P256V1_DOMAIN = new(SM2P256V1);
        public readonly static byte[] DEFAULT_SM2_ID = new byte[] {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        };

        public static (byte[] key, byte[] pub) SM2_GENKEY(bool compressed = false) => SM2_GENKEY(compressed, new SecureRandom());

        public static (byte[] key, byte[] pub) SM2_GENKEY(bool compressed, SecureRandom random) => EC_GENKEY(SM2P256V1_DOMAIN, compressed, random);

        public static (byte[] key, byte[] pub) EC_GENKEY(ECDomainParameters domain, bool compressed = false) => EC_GENKEY(domain, compressed, new SecureRandom());

        public static (byte[] key, byte[] pub) EC_GENKEY(ECDomainParameters domain,bool compressed, SecureRandom random)
        {
            AsymmetricCipherKeyPair ec = Core.GenerateKey("EC", new ECKeyGenerationParameters(domain, random));
            byte[] pub = (ec.Public as ECPublicKeyParameters).Q.GetEncoded(compressed);
            byte[] key = (ec.Private as ECPrivateKeyParameters).D.ToByteArray();
            return (key, pub);
        }

        public static (byte[] key, byte[] pub) RSA_GENKEY(int strength = 2048,int certainty = 25) => RSA_GENKEY(DEFAULT_RSA_PUBLIC_EXPONENT, new SecureRandom(), strength, certainty);

        public static (byte[] key, byte[] pub) RSA_GENKEY(byte[] exponent, SecureRandom random, int strength, int certainty)
        {
            AsymmetricCipherKeyPair rsa = Core.GenerateKey("RSA", new RsaKeyGenerationParameters(new BigInteger(exponent), random, strength, certainty));            
            byte[] pub = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsa.Public).ToAsn1Object().GetEncoded();
            byte[] key = PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsa.Private).ToAsn1Object().GetEncoded();
            return (key, pub);
        }        
    }
}
