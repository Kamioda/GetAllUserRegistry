# Get All User Registry

ローカルコンピューターの全てのアカウントのレジストリキーの値を取得します。

なお、他のユーザーのプロファイルにアクセスするため、実行には管理者権限が必要になります。

また、本プログラムで読み込むことができるのは、基本的には共通で持っているレジストリキーのみです。

## 使い方例
### 全てのユーザーのマイドキュメントのパスを見る

```
GetUserRegistryConsole.exe "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" Personal
```

## 参考サイト

- [ハイブのロード／アンロード](https://www.wabiapp.com/WabiSampleSource/windows/reg_load_key.html)
- [LookupAccountNameW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountnamew)
- [RegLoadKeyW](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw)
- [RegUnLoadKeyW](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regunloadkeyw)
