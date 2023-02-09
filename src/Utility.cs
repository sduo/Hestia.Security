using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;

namespace Hestia.Security
{
    public static partial class Utility
    {
        public static byte[] TrimBlockPadding(byte[] input, int size = 32)
        {
            byte pad = input[^1];
            //if (pad < 1 || pad > size) { pad = 0;}
            return (pad < 1 || pad > size) ? input : input[..(input.Length - pad)];
        }

        public static byte[] PadBlockPadding(long length, int size = 32)
        {
            // 计算需要填充的位数
            int need = size - (int)(length % size);
            //if (need == 0){ need = size;}
            // 获得补位所用的字符
            byte pad = (byte)(need & 0xFF);
            byte[] block = new byte[need];
            Array.Fill(block, pad);
            return block;
        }

        public static byte[] BitConverterGetBytes(uint num, bool bigendian = true) => BitConvert(num, bigendian == BitConverter.IsLittleEndian, BitConverter.GetBytes);
        public static uint BitConverterGetUInt(byte[] data, bool bigendian = true) => BitConvert(data, bigendian == BitConverter.IsLittleEndian, BitConverter.ToUInt32);

        public static byte[] BitConverterGetBytes(int num, bool bigendian = true) => BitConvert(num, bigendian == BitConverter.IsLittleEndian, BitConverter.GetBytes);
        public static int BitConverterGetInt(byte[] data, bool bigendian = true) => BitConvert(data, bigendian == BitConverter.IsLittleEndian, BitConverter.ToInt32);

        public static byte[] BitConverterGetBytes(ulong num, bool bigendian = true) => BitConvert(num, bigendian == BitConverter.IsLittleEndian, BitConverter.GetBytes);
        public static ulong BitConverterGetULong(byte[] data, bool bigendian = true) => BitConvert(data, bigendian == BitConverter.IsLittleEndian, BitConverter.ToUInt64);

        public static byte[] BitConverterGetBytes(long num, bool bigendian = true) => BitConvert(num, bigendian == BitConverter.IsLittleEndian, BitConverter.GetBytes);

        public static long BitConverterGetLong(byte[] data, bool bigendian = true) => BitConvert(data, bigendian == BitConverter.IsLittleEndian, BitConverter.ToInt64);

        public static byte[] BitConvert<T>(T num, bool reverse, Func<T, byte[]> converter)
        {
            byte[] data = converter.Invoke(num);
            if (reverse) { Array.Reverse(data); }
            return data;
        }

        public static T BitConvert<T>(byte[] data, bool reverse, Func<byte[], int, T> converter)
        {
            byte[] copy = new byte[data.Length];
            Array.Copy(data, copy, data.Length);
            if (reverse) { Array.Reverse(copy); }
            T num = converter.Invoke(copy, 0);
            return num;
        }

        public static string OrdinalIgnoreCaseSortConcat(params string[] array) => OrdinalIgnoreCaseSortConcat(string.Empty, array);

        public static string OrdinalIgnoreCaseSortConcat(string separator, params string[] array) => Concat(array, StringComparer.OrdinalIgnoreCase, separator);

        public static string OrdinalSortConcat(params string[] array) => OrdinalSortConcat(string.Empty, array);

        public static string OrdinalSortConcat(string separator, params string[] array) => Concat(array, StringComparer.Ordinal, separator);

        public static string Concat(params string[] array) => Concat(string.Empty, array);
        public static string Concat(string separator, params string[] array) => Concat(array, null, separator);

        public static string Concat(string[] array, StringComparer comparer = null, string separator = null)
        {
            string[] copy = new string[array.Length];
            Array.Copy(array, copy, array.Length);
            if (comparer != null)
            {
                Array.Sort(copy, comparer);
            }
            return string.Join(separator ?? string.Empty, copy);
        }

        public static readonly IDictionary<char, byte> BASE32_DECODE_MAP_APLPHABET = new Dictionary<char, byte>() {
            {'A',0x00 },{'a',0x00 },{'B',0x01 },{'b',0x01 },
            {'C',0x02 },{'c',0x02 },{'D',0x03 },{'d',0x03 },
            {'E',0x04 },{'e',0x04 },{'F',0x05 },{'f',0x05 },
            {'G',0x06 },{'g',0x06 },{'H',0x07 },{'h',0x07 },
            {'I',0x08 },{'i',0x08 },{'J',0x09 },{'j',0x09 },
            {'K',0x0A },{'k',0x0A },{'L',0x0B },{'l',0x0B },
            {'M',0x0C },{'m',0x0C },{'N',0x0D },{'n',0x0D },
            {'O',0x0E },{'o',0x0E },{'P',0x0F },{'p',0x0F },
            {'Q',0x10 },{'q',0x10 },{'R',0x11 },{'r',0x11 },
            {'S',0x12 },{'s',0x12 },{'T',0x13 },{'t',0x13 },
            {'U',0x14 },{'u',0x14 },{'V',0x15 },{'v',0x15 },
            {'W',0x16 },{'w',0x16 },{'X',0x17 },{'x',0x17 },
            {'Y',0x18 },{'y',0x18 },{'Z',0x19 },{'z',0x19 },
            {'2',0x1A },{'3',0x1B },{'4',0x1C },{'5',0x1D },
            {'6',0x1E },{'7',0x1F }
        };

        public static readonly IDictionary<byte, char> BASE32_ENCODE_MAP_APLPHABET = new Dictionary<byte, char>() {
            {0x00,'A'},{0x01,'B'},{0x02,'C'},{0x03,'D' },
            {0x04,'E'},{0x05,'F'},{0x06,'G'},{0x07,'H' },
            {0x08,'I'},{0x09,'J'},{0x0A,'K'},{0x0B,'L' },
            {0x0C,'M'},{0x0D,'N'},{0x0E,'O'},{0x0F,'P' },
            {0x10,'Q'},{0x11,'R'},{0x12,'S'},{0x13,'T' },
            {0x14,'U'},{0x15,'V'},{0x16,'W'},{0x17,'X' },
            {0x18,'Y'},{0x19,'Z'},{0x1A,'2'},{0x1B,'3' },
            {0x1C,'4'},{0x1D,'5'},{0x1E,'6'},{0x1F,'7' }
        };

        public static readonly IDictionary<char, byte> BASE32_DECODE_MAP_EXTENDED_HEX = new Dictionary<char, byte>() {
            {'0',0x00 },{'1',0x01 },{'2',0x02 },{'3',0x03 },
            {'4',0x04 },{'5',0x05 },{'6',0x06 },{'7',0x07 },
            {'8',0x08 },{'9',0x09 },
            {'A',0x0A },{'a',0x0A },{'B',0x0B },{'b',0x0B },
            {'C',0x0C },{'c',0x0C },{'D',0x0D },{'d',0x0D },
            {'E',0x0E },{'e',0x0E },{'F',0x0F },{'f',0x0F },
            {'G',0x10 },{'g',0x10 },{'H',0x11 },{'h',0x11 },
            {'I',0x12 },{'i',0x12 },{'J',0x13 },{'j',0x13 },
            {'K',0x14 },{'k',0x14 },{'L',0x15 },{'l',0x15 },
            {'M',0x16 },{'m',0x16 },{'N',0x17 },{'n',0x17 },
            {'O',0x18 },{'o',0x18 },{'P',0x19 },{'p',0x19 },
            {'Q',0x1A },{'q',0x1A },{'R',0x1B },{'r',0x1B },
            {'S',0x1C },{'s',0x1C },{'T',0x1D },{'t',0x1D },
            {'U',0x1E },{'u',0x1E },{'V',0x1F },{'v',0x1F }
        };

        public static readonly IDictionary<byte, char> BASE32_ENCODE_MAP_EXTENDED_HEX = new Dictionary<byte, char>() {
            {0x00,'0' },{0x01,'1' },{0x02,'2' },{0x03,'3' },
            {0x04,'4' },{0x05,'5' },{0x06,'6' },{0x07,'7' },
            {0x08,'8' },{0x09,'9' },
            {0x0A,'A' },{0x0B,'B' },{0x0C,'C' },{0x0D,'D' },
            {0x0E,'E' },{0x0F,'F' },{0x10,'G' },{0x11,'H' },
            {0x12,'I' },{0x13,'J' },{0x14,'K' },{0x15,'L' },
            {0x16,'M' },{0x17,'N' },{0x18,'O' },{0x19,'P' },
            {0x1A,'Q' },{0x1B,'R' },{0x1C,'S' },{0x1D,'T' },
            {0x1E,'U' },{0x1F,'V' }
        };

        public static readonly IDictionary<char, byte> BASE64_DECODE_MAP_ALPHABET = new Dictionary<char, byte>() {
                { 'A',0x00 },{ 'B',0x01 },{ 'C',0x02 },{ 'D',0x03 },
                { 'E',0x04 },{ 'F',0x05 },{ 'G',0x06 },{ 'H',0x07 },
                { 'I',0x08 },{ 'J',0x09 },{ 'K',0x0A },{ 'L',0x0B },
                { 'M',0x0C },{ 'N',0x0D },{ 'O',0x0E },{ 'P',0x0F },
                { 'Q',0x10 },{ 'R',0x11 },{ 'S',0x12 },{ 'T',0x13 },
                { 'U',0x14 },{ 'V',0x15 },{ 'W',0x16 },{ 'X',0x17 },
                { 'Y',0x18 },{ 'Z',0x19 },
                { 'a',0x1A },{ 'b',0x1B },{ 'c',0x1C },{ 'd',0x1D },
                { 'e',0x1E },{ 'f',0x1F },{ 'g',0x20 },{ 'h',0x21 },
                { 'i',0x22 },{ 'j',0x23 },{ 'k',0x24 },{ 'l',0x25 },
                { 'm',0x26 },{ 'n',0x27 },{ 'o',0x28 },{ 'p',0x29 },
                { 'q',0x2A },{ 'r',0x2B },{ 's',0x2C },{ 't',0x2D },
                { 'u',0x2E },{ 'v',0x2F },{ 'w',0x30 },{ 'x',0x31 },
                { 'y',0x32 },{ 'z',0x33 },
                { '0',0x34 },{ '1',0x35 },{ '2',0x36 },{ '3',0x37 },
                { '4',0x38 },{ '5',0x39 },{ '6',0x3A },{ '7',0x3B },
                { '8',0x3C },{ '9',0x3D },
                { '-',0x3E },{ '+',0x3E },{ '_',0x3F },{ '/',0x3F }
            };

        public static readonly IDictionary<byte, char> BASE64_ENCODE_MAP_ALPHABET = new Dictionary<byte, char>() {
                { 0x00,'A' },{ 0x01,'B' },{ 0x02,'C' },{ 0x03,'D' },
                { 0x04,'E' },{ 0x05,'F' },{ 0x06,'G' },{ 0x07,'H' },
                { 0x08,'I' },{ 0x09,'J' },{ 0x0A,'K' },{ 0x0B,'L' },
                { 0x0C,'M' },{ 0x0D,'N' },{ 0x0E,'O' },{ 0x0F,'P' },
                { 0x10,'Q' },{ 0x11,'R' },{ 0x12,'S' },{ 0x13,'T' },
                { 0x14,'U' },{ 0x15,'V' },{ 0x16,'W' },{ 0x17,'X' },
                { 0x18,'Y' },{ 0x19,'Z' },
                { 0x1A,'a' },{ 0x1B,'b' },{ 0x1C,'c' },{ 0x1D,'d' },
                { 0x1E,'e' },{ 0x1F,'f' },{ 0x20,'g' },{ 0x21,'h' },
                { 0x22,'i' },{ 0x23,'j' },{ 0x24,'k' },{ 0x25,'l' },
                { 0x26,'m' },{ 0x27,'n' },{ 0x28,'o' },{ 0x29,'p' },
                { 0x2A,'q' },{ 0x2B,'r' },{ 0x2C,'s' },{ 0x2D,'t' },
                { 0x2E,'u' },{ 0x2F,'v' },{ 0x30,'w' },{ 0x31,'x' },
                { 0x32,'y' },{ 0x33,'z' },
                { 0x34,'0' },{ 0x35,'1' },{ 0x36,'2' },{ 0x37,'3' },
                { 0x38,'4' },{ 0x39,'5' },{ 0x3A,'6' },{ 0x3B,'7' },
                { 0x3C,'8' },{ 0x3D,'9' },
                { 0x3E,'+' },{ 0x3F,'/' }
            };

        public static readonly IDictionary<byte, char> BASE64_ENCODE_MAP_ALPHABET_SAFE = new Dictionary<byte, char>() {
                { 0x00,'A' },{ 0x01,'B' },{ 0x02,'C' },{ 0x03,'D' },
                { 0x04,'E' },{ 0x05,'F' },{ 0x06,'G' },{ 0x07,'H' },
                { 0x08,'I' },{ 0x09,'J' },{ 0x0A,'K' },{ 0x0B,'L' },
                { 0x0C,'M' },{ 0x0D,'N' },{ 0x0E,'O' },{ 0x0F,'P' },
                { 0x10,'Q' },{ 0x11,'R' },{ 0x12,'S' },{ 0x13,'T' },
                { 0x14,'U' },{ 0x15,'V' },{ 0x16,'W' },{ 0x17,'X' },
                { 0x18,'Y' },{ 0x19,'Z' },
                { 0x1A,'a' },{ 0x1B,'b' },{ 0x1C,'c' },{ 0x1D,'d' },
                { 0x1E,'e' },{ 0x1F,'f' },{ 0x20,'g' },{ 0x21,'h' },
                { 0x22,'i' },{ 0x23,'j' },{ 0x24,'k' },{ 0x25,'l' },
                { 0x26,'m' },{ 0x27,'n' },{ 0x28,'o' },{ 0x29,'p' },
                { 0x2A,'q' },{ 0x2B,'r' },{ 0x2C,'s' },{ 0x2D,'t' },
                { 0x2E,'u' },{ 0x2F,'v' },{ 0x30,'w' },{ 0x31,'x' },
                { 0x32,'y' },{ 0x33,'z' },
                { 0x34,'0' },{ 0x35,'1' },{ 0x36,'2' },{ 0x37,'3' },
                { 0x38,'4' },{ 0x39,'5' },{ 0x3A,'6' },{ 0x3B,'7' },
                { 0x3C,'8' },{ 0x3D,'9' },
                { 0x3E,'-' },{ 0x3F,'_' }
            };

        public static byte[] FromBase32String(string encoded, bool aplphabet = true)
        {
            return FromBaseString(encoded.ToCharArray(), aplphabet ? BASE32_DECODE_MAP_APLPHABET : BASE32_DECODE_MAP_EXTENDED_HEX, 5).ToArray();
        }

        public static byte[] FromBase64String(string encoded)
        {
            return FromBaseString(encoded.ToCharArray(), BASE64_DECODE_MAP_ALPHABET, 6).ToArray();
        }

        public static IEnumerable<byte> FromBaseString(IEnumerable<char> encoded, IDictionary<char, byte> map, int pow)
        {
            byte decoded = 0b_0000_0000;
            var index = 0;
            foreach (var code in encoded)
            {
                if (!map.ContainsKey(code)) { break; }
                var data = map[code];
                for (var i = 0; i < pow; ++i)
                {
                    decoded |= (byte)((byte)(data << (8 - pow + i)) >> 7);
                    if (++index == 8)
                    {
                        yield return decoded;
                        decoded = 0b_0000_0000;
                        index = 0;
                    }
                    decoded <<= 1;
                }
            }
        }

        public static string ToBase32String(byte[] decoded, bool aplphabet = true)
        {
            return string.Concat(ToBaseString(decoded, aplphabet ? BASE32_ENCODE_MAP_APLPHABET : BASE32_ENCODE_MAP_EXTENDED_HEX, 5));
        }

        public static string ToBase64String(byte[] decoded, bool safe = true)
        {
            return string.Concat(ToBaseString(decoded, safe ? BASE64_ENCODE_MAP_ALPHABET_SAFE : BASE64_ENCODE_MAP_ALPHABET, 6));
        }

        public static IEnumerable<char> ToBaseString(IEnumerable<byte> decoded, IDictionary<byte, char> map, int pow)
        {
            byte encoded = 0b_0000_0000;
            var index = 0;
            foreach (var code in decoded)
            {
                for (var i = 0; i < 8; ++i)
                {
                    encoded |= (byte)((byte)(code << i) >> 7);
                    if (++index == pow)
                    {
                        if (!map.ContainsKey(encoded)) { break; }
                        yield return map[encoded];
                        encoded = 0b_0000_0000;
                        index = 0;
                    }
                    encoded <<= 1;
                }
            }
        }

        public static int TruncateOTP(byte[] hash)
        {
            var offset = hash[^1] & 0xF;
            return BitConverterGetInt(hash[offset..(offset + 4)]) & 0x7FFFFFFF;
        }

        public static string FormatOTP(int otp, string fmt)
        {
            var str = otp.ToString(fmt);
            var index = Math.Max(str.Length - fmt.Length, 0);
            return str.Substring(index);
        }

        // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
        public static string HOTP(byte[] key, byte[] counter, string fmt, Func<byte[], byte[], byte[]> mac, Func<byte[], int> truncate, Func<int, string, string> format)
        {
            var hash = mac.Invoke(key, counter);
            var otp = truncate.Invoke(hash);
            return format.Invoke(otp, fmt);
        }

        public static long GetTimeBasedCounter(long ticks, long interval)
        {
            if (interval == 0) { return 0L; }
            var counter = (ticks - DateTimeOffset.UnixEpoch.Ticks) / (interval * TimeSpan.TicksPerSecond);
            return counter;
        }

        // TOTP(K) = HOTP(K,((T - T0) / X)) = Truncate(HMAC-SHA-1(K,(T - T0) / X))
        public static string TOTP(byte[] key, long ticks, long interval, string fmt, Func<byte[], byte[], byte[]> mac, Func<byte[], int> truncate, Func<int, string, string> format)
        {
            var counter = GetTimeBasedCounter(ticks, interval);
            return HOTP(key, BitConverterGetBytes(counter), fmt, mac, truncate, format);
        }

        public static string TOTP(string key, long ticks, long interval = 30,string fmt = "000000")
        {
            return TOTP(FromBase32String(key), ticks, interval, fmt, MAC.HMAC_SHA1, TruncateOTP, FormatOTP);
        }

        public static string TOTP(string key, long interval = 30 ,string fmt = "000000")
        {
            return TOTP(key, DateTimeOffset.UtcNow.Ticks, interval, fmt);
        }
    }

}
