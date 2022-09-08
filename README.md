# Hestia.Security

[![](https://github.com/sduo/Hestia.Security/actions/workflows/main.yml/badge.svg)](https://github.com/sduo/Hestia.Security)
[![](https://img.shields.io/nuget/v/Hestia.Security.svg)](https://www.nuget.org/packages/Hestia.Security)

---
# 应用场景

## 微信支付V2

### 签名

> https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=4_1

* [X] ```MD5```<sup>pass</sup>
* [X] ```HMAC-SHA256```<sup>pass</sup>

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

* [X] ```AES/CBC/NoPadding```<sup>pass</sup>
* [X] ```SHA1```<sup>pass</sup>

## 微信小程序

### 签名

> https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html

* [X] ```SHA1```<sup>pass</sup>

### 服务端获取开放数据

> https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html

* [X] ```AES/CBC/PKCS7PADDING```<sup>pass</sup>

## 钉钉企业内部应用

### 消息订阅加密解密

> https://open.dingtalk.com/document/org/configure-event-subcription

* [X] ```AES/CBC/NOPADDING```<sup>pass</sup>
* [X] ```SHA1 ```<sup>pass</sup>
