using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int n = 0, flag = 0;
            for (int i = 0; i < plainText.Length; i++)//Find the count of the key
            {
                if (cipherText[0] == plainText[i])
                {
                    for (int j = i + 1; j < cipherText.Length; j++)
                    {
                        if (cipherText[1] == plainText[j])
                        {
                            for (int k = j + 1; k < cipherText.Length; k++)
                            {
                                if (cipherText[2] == plainText[k])
                                {
                                    if (k - j == j - i)
                                    {
                                        n = k - j;
                                        flag = 1;
                                        break;
                                    }
                                }
                                else if (k - j > j - i)
                                    break;

                            }
                        }
                        if (flag == 1)
                            break;
                    }
                }
                if (flag == 1)
                    break;
            }

            List<int> key = new List<int>(n);
            int newkey = (int)Math.Ceiling(plainText.Length / (float)n), L = 0;
            char[,] cip = new char[newkey, n];
            for (int i = 0; i < newkey; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (L >= plainText.Length)
                        cip[i, j] = 'x';
                    else
                        cip[i, j] = plainText[L++];
                }
            }

            int pointer = 0, counter = 2;

            for (int i = 0; i < n; i++)
            {
                pointer = flag = 0;
                counter = 2;
                for (int j = 0; j < newkey; j++)
                {

                    if ((pointer >= cipherText.Length || cip[j, i] == cipherText[pointer])) 
                    {
                        flag++;
                        if (flag >= newkey)//3 instead of newkey 3shan kefaya a check 3ala en 3 7rof bas zy b3d
                        { key.Add((int)Math.Ceiling(pointer / (float)newkey)); break; }
                        pointer++;

                    }
                    else
                    {
                        j = -1;
                        pointer = counter++ * newkey - newkey;
                    }
                }
            }
            return key;
        }


        public string Decrypt(string cipherText, List<int> key)
        {

            int T = cipherText.Length / key.Count;
            if (T * key.Count != cipherText.Length)
                return " ";
            else
            {
                char[,] cip = new char[key.Count, T];
                int k = 0;
                string plaintext = "";
                //ba7utaha henna f 2D matrix cip[]
                for (int i = 0; i < key.Count; i++)
                {
                    for (int j = 0; j < T; j++)
                    {
                        cip[i, j] = cipherText[k++];
                    }
                }
                for (int i = 0; i < T; i++)
                {
                    for (int j = 0; j < key.Count; j++)
                    {

                        plaintext += cip[key[j] - 1, i];

                    }
                }
                return plaintext;
            }
           
        }
        public string Encrypt(string plainText, List<int> key)
        {
            string cipher = "";
            int newkey = (int)Math.Ceiling(plainText.Length / (float)key.Count);
            char[,] cip = new char[key.Count,newkey];
            int k = 0,y=1;
            for(int i=0;i<key.Count;i++)
            {               
                for(int j=0;j<newkey;j++)
                {
                    cip[key[i] - 1, j] = plainText[k];
                    k += key.Count;
                    if (k >= plainText.Length)
                        break;
                }
                k = y++;
            }
            for(int i=0;i<key.Count;i++)
            {
                for(int j=0;j<newkey;j++)
                {
                    cipher += cip[i, j];
                }
            }
            return cipher;
        }
    }
}
