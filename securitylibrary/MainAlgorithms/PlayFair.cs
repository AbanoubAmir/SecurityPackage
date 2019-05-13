using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        string alphabet = "abcdefghiklmnopqrstuvwxyz";
        int[] Location;
        char[,] Matrix = new char[5, 5];
        public string Decrypt(string cipherText, string key)
        {
            string plaintext = Construction(cipherText, key);
            string cypher = "";
            int k = 0;
            for (int i = 0; i < plaintext.Length; i += 2)
            {
                if (Location[k + 1] == Location[k + 3])//If same column (I)
                {
                    if((Location[k] - 1)<0)                   
                        cypher += Matrix[(4), Location[k + 1]];                   
                    else
                        cypher += Matrix[(Location[k] - 1), Location[k + 1]];
                    if((Location[k + 2] - 1)<0)
                        cypher += Matrix[(4), Location[k + 3]];
                    else
                        cypher += Matrix[(Location[k + 2] - 1), Location[k + 3]];

                }
                else if (Location[k] == Location[k + 2])//same row
                {
                    if((Location[k + 1] - 1)<0)
                        cypher += Matrix[Location[k], (4)];
                    else
                        cypher += Matrix[Location[k], (Location[k + 1] - 1)];
                    if((Location[k + 3] - 1)<0)
                        cypher += Matrix[Location[k + 2], (4)];
                    else
                        cypher += Matrix[Location[k + 2], (Location[k + 3] - 1)];
                }
                else //intersection
                {
                    cypher += Matrix[Location[k], Location[k + 3]];
                    cypher += Matrix[Location[k + 2], Location[k + 1]];
                }
                k += 4;
            }
            string newcypher = "";
            for(int i=0;i<cypher.Length-2;i++)
            {
                if (cypher[i] == cypher[i + 2] && cypher[i + 1] == 'x')
                {
                    newcypher += cypher[i];
                    i++;
                }
                else if (cypher[i] != cypher[i + 2] && cypher[i + 1] == 'x')
                {
                    newcypher += cypher[i];
                    newcypher += cypher[i + 1];
                    i++;
                }
                else if (cypher[i + 1] != 'x')
                {
                    newcypher += cypher[i];
                    newcypher += cypher[i + 1];
                    i++;
                }
            }
            if (cypher[cypher.Length - 1] != 'x')
            {
                newcypher += cypher[cypher.Length - 2];
                newcypher += cypher[cypher.Length - 1];
            }
            else
                newcypher += cypher[cypher.Length - 2];
            return newcypher;
        }
       
        public string Encrypt(string plainText, string key)
        {
            string plaintext = Construction(plainText, key);
            string cypher = "";
           int k = 0;
            for(int i=0;i<plaintext.Length;i+=2)
            {
                if(Location[k+1]==Location[k+3])//If same column (I)
                {
                    cypher += Matrix[(Location[k] + 1)%5, Location[k+1]];
                    cypher += Matrix[(Location[k+2] + 1)%5, Location[k + 3]];

                }
                else if(Location[k]==Location[k+2])//same row
                {
                    cypher += Matrix[Location[k], (Location[k + 1]+1)%5];
                    cypher += Matrix[Location[k + 2], (Location[k + 3]+1)%5];
                }
                else //intersection
                {
                    cypher += Matrix[Location[k], Location[k + 3]];
                    cypher += Matrix[Location[k + 2], Location[k + 1]];
                }
                k += 4;
            }
            return cypher.ToUpper();
        }

        public string Construction(string plainText, string key)
        {
            plainText = string.Join("", plainText.Split(default(string[]), StringSplitOptions.RemoveEmptyEntries));//Remove spaces from plainText

            char[] NewplainText = plainText.ToLower().ToCharArray();//Change to lower
            char[] newkey = key.ToLower().ToCharArray();

            for (int i = 0; i < NewplainText.Length; i++)//Sub all J with I
            {
                if (NewplainText[i] == 'j')
                {
                    NewplainText[i] = 'i';
                }
            }
            for (int i = 0; i < newkey.Length; i++)//Sub all J with I
            {
                if (newkey[i] == 'j')
                {
                    newkey[i] = 'i';
                }
            }

            string newKey = string.Join("", newkey.Distinct());//Remove duplicate char from Key
            string matrix = string.Join("", (newKey + alphabet).ToCharArray().Distinct());//Add the alphabet to the key and then remove duplicates to create the matrix
            int k = 0;//Iterator for arrays
            for (int i = 0; i < 5; i++)//Convert the matrix string into a 2D array
            {
                for (int j = 0; j < 5; j++)
                {
                    Matrix[i, j] = matrix[k++];
                }
            }
            string plaintext = "";//plaintext after adding X for duplicates
            for (int i = 0; i < NewplainText.Length;)
            {
                //If i=last char meaning it's odd, we add x and if it's duplicate
                if (i == NewplainText.Length - 1 || NewplainText[i] == NewplainText[i + 1])
                {
                    plaintext += NewplainText[i].ToString() + 'x';
                    i++;
                }
                else
                {
                    plaintext += NewplainText[i].ToString() + NewplainText[i + 1].ToString();
                    i += 2;
                }
            }
            Location = new int[plaintext.Length * 2];//Location array for the plaintext 
            k = 0;
            bool flag = false;//to break the loop if the char is found in the 2D matrix
            for (int z = 0; z < plaintext.Length; z++)
            {
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (plaintext[z] == Matrix[i, j])
                        {
                            Location[k++] = i;
                            Location[k++] = j;
                            flag = true;
                            break;
                        }

                    }
                    if (flag)
                    {
                        flag = false;
                        break;
                    }
                }
            }
            return plaintext;
        }

    }
}
