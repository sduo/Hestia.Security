# Hestia.Security

[![](https://github.com/sduo/Hestia.Security/actions/workflows/main.yml/badge.svg)](https://github.com/sduo/Hestia.Security)
[![](https://img.shields.io/nuget/v/Hestia.Security.svg)](https://www.nuget.org/packages/Hestia.Security)

---
# AES

## AES_CBC_PKCS7PADDING

* KEY：16 位
* IV：16 位
* BLOCK：16 位
* 补位：自动补位
* 明文：无限制

```csharp
//加密 
byte[] encrypted = Hestia.Security.CRYPTO.AES_CBC_PKCS7PADDING_ENCRYPT(byte[] key,byte[] iv,byte[] decrypted);
//解密
byte[] decrypted = Hestia.Security.CRYPTO.AES_CBC_PKCS7PADDING_DECRYPT(byte[] key,byte[] iv,byte[] encrypted);
```

## AES_CBC_ZEROBYTEPADDING

* KEY：16 位
* IV：16 位
* BLOCK：16 位
* 补位：自动补位
* 明文：无限制

```csharp
//加密 
byte[] encrypted = Hestia.Security.CRYPTO.AES_CBC_ZEROBYTEPADDING_ENCRYPT(byte[] key,byte[] iv,byte[] decrypted);
//解密
byte[] decrypted = Hestia.Security.CRYPTO.AES_CBC_ZEROBYTEPADDING_DECRYPT(byte[] key,byte[] iv,byte[] encrypted);
```

## AES_CBC_NOPADDING

* KEY：16 位
* IV：16 位
* BLOCK：16 位
* 补位：无
* 明文：必须为 BLOCK 的整数倍

```csharp
//加密 
byte[] encrypted = Hestia.Security.CRYPTO.AES_CBC_NOPADDING_ENCRYPT(byte[] key,byte[] iv,byte[] decrypted);
//解密
byte[] decrypted = Hestia.Security.CRYPTO.AES_CBC_NOPADDING_DECRYPT(byte[] key,byte[] iv,byte[] encrypted);
```

# HASH

## MD5

```csharp
byte[] hash = Hestia.Security.HASH.MD5(byte[] data);
```

## SHA1

```csharp
byte[] hash = Hestia.Security.HASH.SHA1(byte[] data);
```

## SHA256

```csharp
byte[] hash = Hestia.Security.HASH.SHA256(byte[] data);
```

## SHA384

```csharp
byte[] hash = Hestia.Security.HASH.SHA384(byte[] data);
```

## SHA512

```csharp
byte[] hash = Hestia.Security.HASH.SHA512(byte[] data);
```