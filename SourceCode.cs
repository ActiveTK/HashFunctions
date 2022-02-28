
/*!
 *
 * HashFunctions / The Deep T0ols.
 * The Easy CommandLine Hash Tool
 * Copyright (c) 2022 ActiveTK. <webmaster[at]activetk.cf>
 * License: The MIT License
 *
 */

using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace HashFunctions
{
    internal class ChooseFile
    {
        static void Main(string[] args)
        {
            Console.Title = "HashFunctions - The Deep T0ols. Build 2022.02.28";
            var info = new FileHashFunctions();
            if (args.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("!* arg[0] => (string)FilePath > ");
                Console.ResetColor();
                info.FilePath = Console.ReadLine();
            }
            else
            {
                if (args[0].ToLower() == "/explorer" || args[0].ToLower() == "explorer")
                {
                    Console.WriteLine("** レジストリを追加しています。。");
                    Microsoft.Win32.Registry.SetValue(
                        @"HKEY_CLASSES_ROOT\*\shell\HashFunctionsでハッシュを計算\command",
                        "",
                        "\"" + Assembly.GetEntryAssembly().Location + "\" \"%1\""
                    );
                    Console.WriteLine("完了しました。");
                    Environment.Exit(0);
                }
                info.FilePath = args[0];
            }
            var hashlist = info.GetFileHash();
            Console.WriteLine(hashlist);
            try
            {
                System.IO.File.WriteAllText(info.FilePath + ".hash", hashlist);
            }
            catch { }
            Console.Write("!* Press any key to exit..: ");
            Console.ReadKey();
        }

    }
    public class FileHashFunctions
    {
        public string FilePath = "";
        public string GetFileHash()
        {
            var Mes = new StringBuilder();
            Mes.AppendLine("*****************************************************************************");
            Mes.AppendLine("** " + Console.Title);
            Mes.AppendLine("** The Easy CommandLine Hash Tool");
            Mes.AppendLine("** Copyright (c) 2022 ActiveTK. <webmaster[at]activetk.cf>");
            Mes.AppendLine("** License: The MIT License");
            Mes.AppendLine("*****************************************************************************");
            Mes.AppendLine("** DateTime       : " + DateTime.UtcNow + " (UTC)");
            Mes.AppendLine("** Fingerprint    : " + GetRand());
            Mes.AppendLine("*****************************************************************************");
            System.IO.FileInfo fi = new System.IO.FileInfo(FilePath);
            if (!fi.Exists)
            {
                return "ERR: File is NOT exists!";
            }
            Mes.AppendLine("** FileName       : " + fi.Name);
            Mes.AppendLine("** FileSize       : " + fi.Length);
            Mes.AppendLine("** LastWriteTime  : " + fi.LastWriteTime);
            Mes.AppendLine("*****************************************************************************");
            byte[] FileData = System.IO.File.ReadAllBytes(FilePath);
            Mes.AppendLine("** Hash of MD5    : " + GetMD5Hash(FileData));
            Mes.AppendLine("** Hash of SHA1   : " + GetSHA1Hash(FileData));
            Mes.AppendLine("** Hash of SHA256 : " + GetSHA256Hash(FileData));
            Mes.AppendLine("** Hash of SHA384 : " + GetSHA384Hash(FileData));
            Mes.AppendLine("** Hash of SHA512 : " + GetSHA512Hash(FileData));
            Mes.AppendLine("*****************************************************************************");
            return Mes.ToString();
        }
        public static string GetRand()
        {
            byte[] data = new byte[64];
            new RNGCryptoServiceProvider().GetBytes(data);
            var str2 = new StringBuilder();
            foreach (byte byte_ in new MD5CryptoServiceProvider().ComputeHash(data))
                str2.Append(byte_.ToString("x2"));
            return str2.ToString();
        }
        public static string GetMD5Hash(byte[] data)
        {
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            var str2 = new StringBuilder();
            foreach (byte byte_ in new MD5CryptoServiceProvider().ComputeHash(data))
                str2.Append(byte_.ToString("x2"));
            sw.Stop();
            return str2.ToString() + " (" + sw.Elapsed.TotalMilliseconds + "ms)";
        }
        public static string GetSHA1Hash(byte[] data)
        {
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            var str2 = new StringBuilder();
            foreach (byte byte_ in new SHA1CryptoServiceProvider().ComputeHash(data))
                str2.Append(byte_.ToString("x2"));
            sw.Stop();
            return str2.ToString() + " (" + sw.Elapsed.TotalMilliseconds + "ms)";
        }
        public static string GetSHA256Hash(byte[] data)
        {
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            var str2 = new StringBuilder();
            foreach (byte byte_ in new SHA256CryptoServiceProvider().ComputeHash(data))
                str2.Append(byte_.ToString("x2"));
            sw.Stop();
            return str2.ToString() + " (" + sw.Elapsed.TotalMilliseconds + "ms)";
        }
        public static string GetSHA384Hash(byte[] data)
        {
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            var str2 = new StringBuilder();
            foreach (byte byte_ in new SHA384CryptoServiceProvider().ComputeHash(data))
                str2.Append(byte_.ToString("x2"));
            sw.Stop();
            return str2.ToString() + " (" + sw.Elapsed.TotalMilliseconds + "ms)";
        }
        public static string GetSHA512Hash(byte[] data)
        {
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            var str2 = new StringBuilder();
            foreach (byte byte_ in new SHA512CryptoServiceProvider().ComputeHash(data))
                str2.Append(byte_.ToString("x2"));
            sw.Stop();
            return str2.ToString() + " (" + sw.Elapsed.TotalMilliseconds + "ms)";
        }
    }
}
