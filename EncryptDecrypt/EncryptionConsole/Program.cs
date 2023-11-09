// See https://aka.ms/new-console-template for more information
using EncryptionConsole;
using System.Diagnostics;
using System.Globalization;
using System.Text;

//    "Secret": "^!-+=%M?/>XQF^&*b@e190-khiy403Z(?/|x",
//    "Key": "!Yp(>?*$zB9Q8?=+#@!KyX",
//    "Salt": "#@!^N>?/Zr|a;+~"

//string appSecret = "^!-+=%M?/>XQF^&*b@e190-khiy403Z(?/|x";
//string appKey = "!Yp(>?*$zB9Q8?=+#@!KyX";
//string salt = "#@!^N>?/Zr|a;+~";

//string encrypt = AesEncryptionV2.Encrypt(appSecret, appKey, salt);

//Console.WriteLine("Api key :" + encrypt);

//Console.WriteLine();


//string apiKey = "7+blk/EXlWnaI0GkO1C484Ia65aazB5ULqImrq1SAYgid5jlcMU2bBrKyaWCGOUyEhOI74Dz26udqFUZ5wsnJ0ECBxJisWHsyK1G8YrpHis=";

//string textDecrypt = AesEncryptionV2.Decrypt(apiKey, appKey, salt);
//Console.WriteLine(textDecrypt == appSecret);
//Console.WriteLine();


//------------AesEncrytDecryptBase64 --------------
string planText = "AA-202208-0078|LOS|006632";
string secretKey = "abc123";

string cipherText = AesEncrytDecryptBase64.Encrypt(planText, secretKey);
//var x = "iy4lUnXlGiPfj584lsnnkiZk7jxs5oGvtAR35XhbAw2NdtQ0msklg6izmEBpeDmb/EzY1fm+KWPHErWufyK5JA==";
var x = "iy4lUnXlGiPfj584lsnnkj+AgvALVC2CDnibvHYOcrrzc4QzGcqfvA9IrFH0oAkttonrmyhMuYTuPxI9ihxhUQ==";
string planTextResult = AesEncrytDecryptBase64.Decrypt(x, secretKey);
Console.WriteLine(planTextResult);
//Console.WriteLine("cipherText: " + cipherText);

//Console.WriteLine("planTextResult: " + planTextResult);

//Console.WriteLine("planTextResult == planText:" + planTextResult.Equals(planText));

//Console.WriteLine();

Console.WriteLine(DateTime.Now.ToString("yyyyMMdd", new CultureInfo("th-TH")));

Process myProcess = new Process();
myProcess.StartInfo.UseShellExecute = true;
//myProcess.StartInfo.FileName = $"https://localhost:7201/WWWS1/CalTCGScoring?token={x}";
//myProcess.StartInfo.FileName = $"https://cisuat.exim.go.th/WWWS1/CalTCGScoring?token={x}";
myProcess.StartInfo.FileName = $"https://cis.exim.go.th/WWWS1/CalTCGScoring?token={x}";
myProcess.Start();