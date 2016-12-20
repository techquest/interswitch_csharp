using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Utilities.Encoders;

namespace Interswitch
{
    class AppUtils
    {

        public static byte[] hexConverter(String str)
        {
            byte[] myBytes = Hex.Decode(str);
            return myBytes;
        }

        public static String padLeft(String data, int maxLen, String padStr)
        {
            if (data == null || data.Length >= maxLen)
                return data;
            int len = data.Length;
            int deficitLen = maxLen - len;
            for (int i = 0; i < deficitLen; i++)
                data = padStr + data;
            return data;
        }

        public static String padRight(String data, int maxLen, String padStr)
        {
            if (data == null || data.Length >= maxLen)
                return data;
            int len = data.Length;
            int deficitLen = maxLen - len;
            for (int i = 0; i < deficitLen; i++)
                data += padStr;
            return data;
        }


        public static void zeroise(byte[] data)
        {
            int len = data.Length;

            for (int i = 0; i < len; i++)
                data[i] = 0;
        }

        public static Boolean isNullOrEmpty(String str)
        {
            return str == null || str.Equals("");
        }


    }
}
