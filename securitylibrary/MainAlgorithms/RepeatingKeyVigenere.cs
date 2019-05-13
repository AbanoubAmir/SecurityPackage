using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[,] tableu = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                int k = i;
                for (int j = 0; j < 26; j++)
                {
                    tableu[i, j] = alphabet[k % 26];
                    k++;
                }
            }
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string keystream = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int n = plainText[i] - 97;
                char c = cipherText[i];
                for (int j = 0; j < 26; j++)
                {
                    if (tableu[n, j] == c)
                    {
                        keystream += Convert.ToChar(j + 97);
                        break;
                    }
                }
            }
            int counter = 0;
            string key = "";

            for (int j = 1; j < keystream.Length; j++)
            {
                if (keystream[0] == keystream[j])
                {
                    int point = 1;
                    counter = 0;
                    for (int k = j + 1; k < keystream.Length; k++)
                    {
                        if (keystream[point++] == keystream[k])
                        {
                            counter++;
                            if (counter > 3)
                            {
                                counter = -1;
                                break;
                            }
                        }
                        else
                            break;
                    }
                    if (counter == -1)
                    {
                        key = keystream.Substring(0, j);
                        break;
                    }
                }
                if (j == keystream.Length - 1)
                    key = keystream;
            }
            return key;
        }



        public string Decrypt(string cipherText, string key)
        {
            key = key.ToUpper();
            cipherText = cipherText.ToUpper();
            string plaintext = "";
            if (key.Length < cipherText.Length)
            {
                int diff = cipherText.Length - key.Length;
                for (int i = 0; i < diff; i++)
                {
                    key += key[i];
                }
            }
            for (int i = 0; i < key.Length; i++)
            {

                plaintext += Convert.ToChar((((cipherText[i] - 65) - (key[i] - 65) + 26) % 26) + 65);
            }
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToUpper();
            plainText = plainText.ToUpper();
            string cipher = "";
            if(key.Length<plainText.Length)
            {
                int diff = plainText.Length - key.Length;
                for(int i=0;i<diff;i++)
                {
                    key += key[i];
                }
            }
            for (int i = 0; i < key.Length; i++)
            {

                cipher += Convert.ToChar((((plainText[i] - 65) + (key[i] - 65)) % 26) + 65);
            }
            return cipher;
        }
    }
}