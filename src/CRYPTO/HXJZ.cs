using System;
using System.Collections.Generic;
using System.Text;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        public const string HXJZ_WORD_MAP = "富强民主文明和谐自由平等公正法治爱国敬业诚信友善";
        public const string HXJZ_CHAR_MAP = "0123456789ABCDEF";


        private static string HXJZ_ENCODE(List<int> input)
        {
            StringBuilder output = new();
            foreach (int i in input)
            {
                output.Append(HXJZ_WORD_MAP[i * 2]);
                output.Append(HXJZ_WORD_MAP[i * 2 + 1]);
            }
            return output.ToString();
        }

        private static List<int> HXJZ_DECODE(string input)
        {
            List<int> output= new();
            foreach(char x in input)
            {
                int index = HXJZ_WORD_MAP.IndexOf(x);
                if (index == -1) { continue; }
                if (1 == (index & 1)) { continue; }
                output.Add(index >> 1);
            }            
            return output;

        }

        public static string HXJZ_ENCRYPT(string input)
        {
            string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(input));
            List<int> raw = new();
            foreach (char x in hex)
            {
                int index = HXJZ_CHAR_MAP.IndexOf(x);
                if (index == -1) { continue; }
                if (index < 10)
                {
                    raw.Add(index);
                }
                else if (Random.Shared.Next(0, 1) == 0)
                {
                    raw.Add(10);
                    raw.Add(index - 10);
                }
                else
                {
                    raw.Add(11);
                    raw.Add(index - 6);
                }
            }
            return HXJZ_ENCODE(raw);
        }

        public static string HXJZ_DECRYPT(string input)
        {
            List<int> raw = HXJZ_DECODE(input);
            var index = 0;
            StringBuilder hex = new ();
            while (index < raw.Count)
            {
                int x = raw[index];
                if(x < 10) 
                { 
                    hex.Append(HXJZ_CHAR_MAP[x]); 
                }
                else if (x == 10)
                {
                    index += 1;
                    hex.Append(HXJZ_CHAR_MAP[raw[index] + 10]);
                }
                else
                {
                    index += 1;
                    hex.Append(HXJZ_CHAR_MAP[raw[index] + 6]);
                }
                index += 1;
            }
            return Encoding.UTF8.GetString(Convert.FromHexString(hex.ToString()));
        }
    }
}
