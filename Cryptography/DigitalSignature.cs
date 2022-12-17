using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Cryptography
{
    public class DigitalSignature
    {
        public static string EncryptText(string plainText, RSAParameters publicKey)
        {
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();

            csp.ImportParameters(publicKey);

            var bytesPlainText = System.Text.Encoding.Unicode.GetBytes(plainText);
            var bytesCypherText = csp.Encrypt(bytesPlainText, false);

            return Convert.ToBase64String(bytesCypherText);
        }
        public static string DecryptText(string cypherText, RSAParameters privateKey)
        {

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();

            csp.ImportParameters(privateKey);

            var bytesCypherText = Convert.FromBase64String(cypherText);
            var bytesPlainText = csp.Decrypt(bytesCypherText, false);

            return Encoding.Unicode.GetString(bytesPlainText);
        }

        public static string Hash(string plainText)
        {
            SHA256Managed managed = new SHA256Managed();
            StringBuilder hash = new StringBuilder();

            byte[] computeHash = managed.ComputeHash(Encoding.UTF8.GetBytes(plainText));

            foreach (byte b in computeHash)
            {
                hash.Append(b.ToString("x2"));
            }

            return hash.ToString();
        }

        public static RSAParameters StringToRSAParameters(string key)
        {
            var sr = new System.IO.StringReader(key);
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            return (RSAParameters)xs.Deserialize(sr);
        }
    }
}
