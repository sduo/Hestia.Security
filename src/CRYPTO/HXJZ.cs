using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        public static readonly string[] E = new string[] { "富强","民主","文明","和谐","自由","平等","公正","法治","爱国","敬业","诚信","友善" };
        public static readonly char[] M = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };



        public static void HXJZ(string input)
        {
            string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(input));
            List<int> duo = new();
            Array.ForEach<int>(hex.Select(x => Array.IndexOf(M, x)).ToArray(), (x) => {
                if (x < 10) { 
                    duo.Add(x);
                }
                else if(Random.Shared.Next(0,1) == 0) 
                {
                    duo.Add(10);
                    duo.Add(x - 10);
                }
                else
                {
                    duo.Add(11);
                    duo.Add(x - 6);
                }
            });
            string output =string.Concat( duo.Select(x => E[x]));
           

        }
    }
}
