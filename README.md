# FileExtensionValidation 方案
> 參考自 [安全框架︰輸入驗證 | 風險降低](https://docs.microsoft.com/zh-tw/azure/security/develop/threat-modeling-tool-input-validation)確定在接受使用者的檔案時已備妥適當的控制 區段中的程式碼，再加以調整。
主要就是讀取檔案中的 signatures(magic numbers or Magic Bytes) 來比較。


## 專案說明
|專案|說明|.NET版本|
|---|---|---|
|FileExtensionValidation| fileSignature 變數記錄附檔名及檔案的 Signatures(包含Offset), IsValidFileExtension Method提供驗證檔案內容是否與附檔名相同。|.NET Standard 2.0|
|FileExtensionValidation.Test|FileExtensionValidation的測試程式，測試檔案會放置在Files目錄之中|.NET 4.6.2|

## How do I install it?

FileExtensionValidation is available on NuGet, so can be installed via the Package Manager:

```
Install-Package FileExtensionValidation
```


## 使用方式

### 傳入 File ByteArrays

```csharp
var fileName = "1.jpg";
var filePath = Path.Combine(_folderPath, fileName);
var fileData = File.ReadAllBytes(filePath);
var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);
//isValidFileExtension: true 表示通過，false 表示內容與附檔名不符
```

### 傳入 FileStream

```csharp
var fileName = "1.jpg";
var filePath = Path.Combine(_folderPath, fileName);
var fs = File.OpenRead(filePath);
var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fs, null);
//isValidFileExtension: true 表示通過，false 表示內容與附檔名不符
```

>註:如果不在驗證的檔案清單中，預設會回傳 False 哦!

## 目前 Support 的附檔名

| 附檔名
|--------
| .jpg
| .odt
| .ods
| .xlsx
| .xls
| .avi
| .mov
| .wmv
| .jpeg
| .txt
| .7z
| .gif
| .rm
| .png
| .pdf
| .odp
| .wav
| .odg
| .3pg
| .m4v
| .mkv
| .bmp
| .mp4
| .mpg
| .rar
| .mp3
| .tif
| .mpeg
| .zip
| .rtf
| .ppt
| .pptx
| .doc
| .docx


## 參考資料
[List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)

[File Signatures](https://www.filesignatures.net/index.php)

[GCK'S FILE SIGNATURES TABLE](https://www.garykessler.net/library/file_sigs.html)

## Get Feedback
- [Sharon Tseng (曾佩萱)](mailto:sharon_tseng@gss.com.tw)
- [Rainmaker Ho(亂馬客)](mailto:rainmaker_ho@gss.com.tw)

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
