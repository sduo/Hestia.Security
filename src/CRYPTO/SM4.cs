﻿using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        public static byte[] SM4_CBC_PKCS7PADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_PKCS7PADDING(false, key, iv, input);

        public static byte[] SM4_CBC_PKCS7PADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_PKCS7PADDING(true, key, iv, input);

        private static byte[] SM4_CBC_PKCS7PADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("SM4/CBC/PKCS7PADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        public static byte[] SM4_CBC_ZEROBYTEPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_ZEROBYTEPADDING(false, key, iv, input);

        public static byte[] SM4_CBC_ZEROBYTEPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_ZEROBYTEPADDING(true, key, iv, input);

        private static byte[] SM4_CBC_ZEROBYTEPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("SM4/CBC/ZEROBYTEPADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);

        public static byte[] SM4_CBC_NOPADDING_DECRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_NOPADDING(false, key, iv, input);

        public static byte[] SM4_CBC_NOPADDING_ENCRYPT(byte[] key, byte[] iv, byte[] input) => SM4_CBC_NOPADDING(true, key, iv, input);

        private static byte[] SM4_CBC_NOPADDING(bool encrypt, byte[] key, byte[] iv, byte[] input) => Core.Crypto("SM4/CBC/NOPADDING", encrypt, new ParametersWithIV(new KeyParameter(key), iv), input);
    }
}