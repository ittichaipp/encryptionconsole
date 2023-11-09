using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionConsole
{
    public static class AesEncryptionV2
    {
        public static string Decrypt(string cipherText, string encryptionKey, string salt)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");

            if (encryptionKey == null || encryptionKey.Length <= 0)
                throw new ArgumentNullException("encryptionKey");

            if (salt == null || salt.Length <= 0)
                throw new ArgumentNullException("salt");

            byte[] bSalt = Encoding.ASCII.GetBytes(salt);

            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, bSalt);
                
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }

        public static string Encrypt(string plainText, string encryptionKey, string salt)
        {
            String encryptedText = "";

            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");

            if (encryptionKey == null || encryptionKey.Length <= 0)
                throw new ArgumentNullException("encryptionKey");

            if (salt == null || salt.Length <= 0)
                throw new ArgumentNullException("salt");

            byte[] bSalt = Encoding.ASCII.GetBytes(salt);

            byte[] plainTextByte = Encoding.Unicode.GetBytes(plainText);
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, bSalt);

                aesAlg.Key = pdb.GetBytes(32);
                aesAlg.IV = pdb.GetBytes(16);

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {

                        csEncrypt.Write(plainTextByte, 0, plainTextByte.Length);
                        csEncrypt.Close();
                        encryptedText = Convert.ToBase64String(msEncrypt.ToArray());

                    }
                }
            }


            return encryptedText;
        }
    }
}
