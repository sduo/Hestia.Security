using System;

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

        public static byte[] PadBlockPadding(long length,int size = 32)
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

        public static byte[] BitConvert<T>(T num,bool reverse, Func<T, byte[]> converter)
        {
            byte[] data = converter.Invoke(num);
            if (reverse) { Array.Reverse(data); }
            return data;
        }

        public static T BitConvert<T>(byte[] data,bool reverse, Func<byte[],int,T> converter)
        {
            byte[] copy = new byte[data.Length];
            Array.Copy(data,copy,data.Length);
            if (reverse) { Array.Reverse(copy); }
            T num = converter.Invoke(copy, 0);
            return num;
        }

        public static string OrdinalIgnoreCaseSortConcat(params string[] array) => OrdinalIgnoreCaseSortConcat(string.Empty, array);

        public static string OrdinalIgnoreCaseSortConcat(string separator, params string[] array) => Concat(array, StringComparer.OrdinalIgnoreCase, separator);

        public static string OrdinalSortConcat(params string[] array) => OrdinalSortConcat(string.Empty,array);

        public static string OrdinalSortConcat(string separator, params string[] array) => Concat(array, StringComparer.Ordinal, separator);

        public static string Concat(params string[] array) => Concat(string.Empty, array);
        public static string Concat(string separator, params string[] array) => Concat(array, null, separator);

        public static string Concat(string[] array, StringComparer comparer=null, string separator = null)
        {
            string[] copy = new string[array.Length];
            Array.Copy(array,copy,array.Length);
            if (comparer != null)
            {
                Array.Sort(copy, comparer);
            }            
            return string.Join(separator ?? string.Empty, copy);
        }
    }
}
