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
byte[] encrypted = Utility.AES128_CBC_PKCS7_ENCRYPT(byte[] key,byte[] iv,byte[] decrypted);
//解密
byte[] decrypted = Utility.AES128_CBC_PKCS7_ENCRYPT(byte[] key,byte[] iv,byte[] encrypted);
```


