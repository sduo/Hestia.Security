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