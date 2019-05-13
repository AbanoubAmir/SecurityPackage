using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            char second = cipherText[1];
            int Key = 0;

            for (int i = 0; i < plainText.Length; i++)
            {

                if (plainText[i] == second && plainText[i + 1] == second)
                {
                    Key = i + 1;
                    break;
                }
                else if (plainText[i] == second)
                {
                    Key = i;
                    break;
                }
            }

            return Key;

        }

        public string Decrypt(string cipherText, int key)
        {
            string plaintext = "";
            int i = 0, k=1;
            key = (int)Math.Ceiling(cipherText.Length / (float)key);
            while (true)
            {
                plaintext += cipherText[i];
                i += key;
                if (i >= cipherText.Length)
                {
                    i = k++;
                }
                if (plaintext.Length == cipherText.Length)
                    break;
            }
            return plaintext;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipher = "";
            int i = 0,k=1;
            while(true)
            {
                cipher += plainText[i];
                i += key;
                if(i>=plainText.Length)
                {
                    i = k++;
                }
                if (cipher.Length == plainText.Length)
                    break;
            }
            return cipher;
            //throw new NotImplementedException();
        }
    }
}
