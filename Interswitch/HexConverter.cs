using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Interswitch
{
    public class HexConverter
    {



        /***
         * @author Evans Erhobaga-Agofure
         * 
         */


        /*=======================================================================*/
        /*	CONSTRUCTOR										 					 */
        /*=======================================================================*/
        public HexConverter()
        {
        }

        /*=======================================================================*/
        /*	IMPLEMENTED METHODS									 	 			 */
        /*=======================================================================*/


        public static string ByteArrayToString(byte[] ba)
        {
            //StringBuilder hex = new StringBuilder(ba.Length * 2);
            //foreach (byte b in ba)
            //  hex.AppendFormat("{0:x2}", b);
            //return hex.ToString();

            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");

        }
        public static string ByteArrayToString2(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:X2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }


    }
}