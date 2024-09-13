# Hestia.Security

[![](https://github.com/sduo/Hestia.Security/actions/workflows/main.yml/badge.svg)](https://github.com/sduo/Hestia.Security)
[![](https://img.shields.io/nuget/v/Hestia.Security.svg)](https://www.nuget.org/packages/Hestia.Security)

---
# 应用场景

## 微信支付V2

### 签名

> https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=4_1

* [X] ```MD5```
    * [X] HASH/MD5/Test2
* [X] ```HMAC-SHA256```
    * [X] MAC/HMAC_SHA256/Test2

## 微信支付V3

### 签名

> https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay3_3.shtml

* [X] ```SHA256withRSA```

### 证书和回调报文解密

> https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay3_2.shtml

* [X] ```AES/GCM/NoPadding```

### 敏感信息加解密

> https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_3.shtml

* [X] ```RSA/ECB/OAEPWithSHA-1AndMGF1Padding```

## 微信第三方平台

### 消息加解密

> https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/api/Before_Develop/Technical_Plan.html

* [X] ```AES/CBC/NoPadding```
    * [X] CRYPTO/AES_CBC_NOPADDING/Test3
    * [X] CRYPTO/AES_CBC_NOPADDING/Test4
* [X] ```SHA1```
    * [X] HASH/SHA1/Test3

## 微信小程序

### 签名

> https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html

* [X] ```SHA1```
    * [X] HASH/SHA1/Test2

### 服务端获取开放数据

> https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html

* [X] ```AES/CBC/PKCS7PADDING```
    * [X] CRYPTO/AES_CBC_PKCS7PADDING/Test3
    * [X] CRYPTO/AES_CBC_PKCS7PADDING/Test4

## 支付宝接口内容加密

> https://opendocs.alipay.com/common/02mse3
> https://github.com/alipay/alipay-sdk-net-all/blob/master/v2/AlipaySDKNet.Standard/Util/AlipayEncrypt.cs

* [X] ```AES_CBC_PKCS7PADDING```
    * [X] CRYPTO/AES_CBC_PKCS7PADDING/Test7
    * [X] CRYPTO/AES_CBC_PKCS7PADDING/Test8

## 支付宝密钥工具

### 签名

> https://opendocs.alipay.com/common/02kipk

* [X] ```SHA256WITHRSA```
    * [X] SIGN/SHA256_WITH_RSA/Test6



## 钉钉企业内部应用

### 消息订阅加密解密

> https://open.dingtalk.com/document/org/configure-event-subcription

* [X] ```AES/CBC/NOPADDING```
    * [X] CRYPTO/AES_CBC_NOPADDING/Test5
    * [X] CRYPTO/AES_CBC_NOPADDING/Test6
* [X] ```SHA1 ```
    * [X] HASH/SHA1/Test4

## 钉钉机器人

### 自定义机器人签名

> https://open.dingtalk.com/document/robots/customize-robot-security-settings

* [X] ```HMAC-SHA256```
    * [X] MAC/HMAC_SHA256/Test3

## 淘宝开放平台

### 签名

> https://open.taobao.com/doc.htm?docId=101617&docType=1

* [X] ```MD5```
    * [X] HASH/MD5/Test3
* [X] ```HMAC-MD5```
    * [X] MAC/HMAC_MD5/Test2
    ```csharp
    // https://try.dot.net/
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    public class Program
    {
        public static void Main()
        {
            string source = "app_key12345678fieldsnum_iid,title,nick,price,numformatjsonmethodtaobao.item.seller.getnum_iid11223344sessiontestsign_methodmd5timestamp2016-01-01 12:00:00v2.0";
            string key = "helloworld";
            HMACMD5 hmac = new HMACMD5(Encoding.UTF8.GetBytes(key));
            byte[] data = hmac.ComputeHash(Encoding.UTF8.GetBytes(source));
            string hex = string.Concat(data.Select(x=>x.ToString("X2"))); // B4DDA503460D60A86B16E950E5D303E9
            Console.WriteLine(hex);
        }
    }
    ```
* [ ] ```HMAC-SHA256```

## 阿里云接口

### 签名

> https://help.aliyun.com/document_detail/315526.html

* [X] ```HMAC-SHA1```
    * [X] MAC/HMAC_SHA1/Test2

## 阿里云 API 网关

### JWT 签名

> https://help.aliyun.com/document_detail/177489.html

* [X] ```SHA256withRSA```
    * [X] SIGN/SHA256_WITH_RSA/Test4

## 财政电子票据对接报文消息摘要

> 财政电子票据对接报文规范-开票报文
>
> 财政电子票据对接报文规范-入账报文
>
> 财政电子票据对接报文规范-数据交换报文
>
> 附录B-消息摘要

* [X] ```SHA256```
    * [X] HASH/SHA256/Test2
* [X] ```SM3```
    * [X] HASH/SM3/Test2

```java
// https://www.jdoodle.com/online-java-compiler-ide/
// Test on JDK 17.0.1
// lib add commons-codec:commons-codec:1.15
import org.apache.commons.codec.digest.DigestUtils;
// lib add org.bouncycastle:bcprov-jdk15on:1.70
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.UnsupportedEncodingException;

public class CzClass {
    public static void main(String args[]) {
        String xml ="<?xml version='1.0' encoding='UTF-8'?><Invoice><Head><MsgNo>8901</MsgNo><Version>1.0</Version><AppId>KPQZDWB5629411</AppId><MsgId>20190522213800999</MsgId><DateTime>20190522213800999</DateTime><Resvered></Resvered></Head><Msg>PFZvdWNoZXI+PFBsYWNlQ29kZT4wMDE8L1BsYWNlQ29kZT48L1ZvdWNoZXI+</Msg></Invoice>";
		System.out.println("xml:"+xml);
		String APP_KEY = "TEST_APP_KEY";
        System.out.println("APP_KEY:"+APP_KEY);
		String source = APP_KEY + xml;
		System.out.println("source:"+source);
		
		// sha256
		String sha256 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(source);
		System.out.println("sha256:"+sha256);
		
		// sm3
		try {
    		byte[] data = source.getBytes("UTF-8");
    		SM3Digest digest = new SM3Digest();
    		digest.update(data, 0, data.length);
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            String sm3 = ByteUtils.toHexString(hash);
            System.out.println("sm3:"+sm3);
		} catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
}
```

```
xml:<?xml version='1.0' encoding='UTF-8'?><Invoice><Head><MsgNo>8901</MsgNo><Version>1.0</Version><AppId>KPQZDWB5629411</AppId><MsgId>20190522213800999</MsgId><DateTime>20190522213800999</DateTime><Resvered></Resvered></Head><Msg>PFZvdWNoZXI+PFBsYWNlQ29kZT4wMDE8L1BsYWNlQ29kZT48L1ZvdWNoZXI+</Msg></Invoice>
APP_KEY:TEST_APP_KEY
source:TEST_APP_KEY<?xml version='1.0' encoding='UTF-8'?><Invoice><Head><MsgNo>8901</MsgNo><Version>1.0</Version><AppId>KPQZDWB5629411</AppId><MsgId>20190522213800999</MsgId><DateTime>20190522213800999</DateTime><Resvered></Resvered></Head><Msg>PFZvdWNoZXI+PFBsYWNlQ29kZT4wMDE8L1BsYWNlQ29kZT48L1ZvdWNoZXI+</Msg></Invoice>
sha256:09be4a8404ae81630c4bc6fb6c58df816a724d48e7ff2dd22ff79d87e43f342a
sm3:34a137b8bba3b6eefbee72eac423eddefc67048ba9e1fa725139ad596e8dedf4
```

## 链上公益

### 接口加解密

* [X] ```RSA/ECB/PKCS1Padding```
* [X] ```AES/ECB/PKCS5Padding```
* [X] ```SHA256```
* [X] ```SHA-256withRSA```

## 腾讯公募系统

### 签名

> 腾讯公益与公募机构电子发票对接文档(2023-07-17 15:07)

* [X] ```SHA256```
    * [X] HASH/SHA256/Test3

```bash
echo -n 'key1=v1&key2=v2&key3=v3...' | sha256sum
```

## 腾讯公益开放平台

### 签名

> https://open.gongyi.qq.com/docs/server_api/%E5%BC%80%E5%8F%91%E5%89%8D%E5%BF%85%E8%AF%BB/%E6%8E%A5%E5%8F%A3%E8%B0%83%E7%94%A8%E5%87%AD%E8%AF%81.html#%E5%BA%94%E7%94%A8%E7%AD%BE%E5%90%8D

* [X] ```HMAC-SHA256```
    * [X] MAC/HMAC_SHA256/Test4

## 字节跳动公益票据

### 签名

> https://lingxi.feishu.cn/docx/WYwdd7CFvo0enXxAjvicfM2KnXg

* [X] ```SHA256```
    * [X] HASH/SHA256/Test4 

## TOTP

* [X] ```HMAC-SHA1```
    * [X] Utility/OTP/Test9

# 感谢
* https://www.rfc-editor.org/rfc/rfc2104
* https://www.rfc-editor.org/rfc/rfc4226
* https://www.rfc-editor.org/rfc/rfc6238