using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hestia.Security.Tests.CRYPTO
{
    [TestClass]
    [ExcludeFromCodeCoverage]
    public sealed class BJX
    {        
        private const string encrypted = "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜戚谢邹喻福水窦章云苏潘葛奚潘彭郎鲁韦昌马苗凤花方俞任袁柳唐罗薛伍余米贝姚孟顾尹江钟";
        private const string decrypted = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ.–_+=/?#%&*";

        [TestMethod]
        public void Test1()
        {
            Assert.AreEqual(encrypted, Security.CRYPTO.BJX_ENCRYPT(decrypted));
        }
        [TestMethod]
        public void Test2()
        {
            Assert.AreEqual(decrypted, Security.CRYPTO.BJX_DECRYPT(encrypted));
        }
    }
}
