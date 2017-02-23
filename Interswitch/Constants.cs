using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Interswitch
{
    public class Constants
    {
        public static string SANDBOX_URL = "https://sandbox.interswitch.ng";
        //public static string SANDBOX_URL = "https://sandbox.interswitchng.com";
        public static string PRODUCTION_URL = "https://saturn.interswitchng.com";
        public static string DEVELOPMENT_URL = "http://172.25.20.56:9080";

        public static string Contenttype = "content-type";
        public static string Cachecontrol = "cache-control";
        public static string Authorization = "Authorization";
        public static string ContentType = "application/x-www-form-urlencoded";

        public static String CARD_NAME = "default";
        public static String SECURE_HEADER = "4D";
        //public static String SECURE_FORMAT_VERSION = "11";
        public static String SECURE_FORMAT_VERSION = "12";
        public static String SECURE_MAC_VERSION = "05";
        public static String SECURE_FOOTER = "5A";
        public static String SIGNATURE_HEADER = "Signature";
        public static String SIGNATURE_METHOD_HEADER = "SignatureMethod";

    }
}
