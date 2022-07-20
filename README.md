# Hestia.Security

[![](https://github.com/sduo/Hestia.Security/actions/workflows/main.yml/badge.svg)](https://github.com/sduo/Hestia.Security)
[![](https://img.shields.io/nuget/v/Hestia.Security.svg)](https://www.nuget.org/packages/Hestia.Security)

---
# AES

## AES128_CBC_PKCS7

* KEY：16 位
* IV：16 位

```csharp
//加密 
byte[] encrypted = Hestia.Security.AES128_CBC_PKCS7_ENCRYPT(byte[] key,byte[] iv,byte[] decrypted);
//解密
byte[] decrypted = Hestia.Security.AES128_CBC_PKCS7_ENCRYPT(byte[] key,byte[] iv,byte[] encrypted);
```

## AES128_CBC_ZERO

* KEY：16 位
* IV：16 位

```csharp
//加密 
byte[] encrypted = Hestia.Security.AES.AES128_CBC_ZERO_ENCRYPT(byte[] key,byte[] iv,byte[] decrypted);
//解密
byte[] decrypted = Hestia.Security.AES.AES128_CBC_ZERO_DECRYPT(byte[] key,byte[] iv,byte[] encrypted);
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