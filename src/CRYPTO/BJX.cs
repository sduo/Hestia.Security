using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security
{
    public static partial class CRYPTO
    {
        public static readonly char[] BJX_ENCRYPTED = new char[] {
            '赵','钱','孙','李','周','吴','郑','王','冯','陈',
            '褚','卫','蒋','沈','韩','杨','朱','秦','尤','许',
            '何','吕','施','张','孔','曹','严','华','金','魏',
            '陶','姜','戚','谢','邹','喻','福','水','窦','章',
            '云','苏','潘','葛','奚','范','彭','郎','鲁','韦',
            '昌','马','苗','凤','花','方','俞','任','袁','柳',
            '唐','罗','薛','伍','余','米','贝','姚','孟','顾',
            '尹','江','钟'
        };
        public static readonly char[] BJX_DECRYPTED = new char[] {
             '0','1','2','3','4','5','6','7','8','9',
             'a','b','c','d','e','f','g','h','i','j',
             'k','l','m','n','o','p','q','r','s','t',
             'u','v','w','x','y','z','A','B','C','D',
             'E','F','G','H','I','J','K','L','M','N',
             'O','P','Q','R','S','T','U','V','W','X',
             'Y','Z','.','–','_','+','=','/','?','#',
             '%','&','*'
        };

        public static string BJX_ENCRYPT(string input)
        {
            return string.Concat(input.Select(BJX_ENCRYPT));
        }

        public static string BJX_DECRYPT(string input)
        {
            return string.Concat(input.Select(BJX_DECRYPT));
        }

        public static char BJX_DECRYPT(char input) => BJX(input, BJX_ENCRYPTED, BJX_DECRYPTED);

        public static char BJX_ENCRYPT(char input) => BJX(input, BJX_DECRYPTED, BJX_ENCRYPTED);

        private static char BJX (char input, char[] source, char[] target)
        {
            var index = Array.IndexOf (source, input);
            if (index == -1) { throw new IndexOutOfRangeException(); }
            return target[index];
        }
    }
}
