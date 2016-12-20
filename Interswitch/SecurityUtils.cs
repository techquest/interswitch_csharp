using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace Interswitch
{
    public class SecurityUtils
    {

        protected static String publicKeyExponent = "010001";
        protected static String publicKeyModulus = "009C7B3BA621A26C4B02F48CFC07EF6EE0AED8E12B4BD11C5CC0ABF80D5206BE69E1891E60FC88E2D565E2FABE4D0CF630E318A6C721C3DED718D0C530CDF050387AD0A30A336899BBDA877D0EC7C7C3FFE693988BFAE0FFBAB71B25468C7814924F022CB5FDA36E0D2C30A7161FA1C6FB5FBD7D05ADBEF7E68D48F8B6C5F511827C4B1C5ED15B6F20555AFFC4D0857EF7AB2B5C18BA22BEA5D3A79BD1834BADB5878D8C7A4B19DA20C1F62340B1F7FBF01D2F2E97C9714A9DF376AC0EA58072B2B77AEB7872B54A89667519DE44D0FC73540BEEAEC4CB778A45EEBFBEFE2D817A8A8319B2BC6D9FA714F5289EC7C0DBC43496D71CF2A642CB679B0FC4072FD2CF";



        public static String GetAuthData(string pan, string pin, string expiryDate, string cvv2, string modulus = null, string pubExpo = null)
        {
            if (pan != null)
            {
                pan = pan.Trim();
            }
            else
            {
                pan = "";
            }
            if (pan != null)
            {
                pan = pan.Trim();
            }
            else
            {
                pan = "";
            }
            if (cvv2 != null)
            {
                cvv2 = cvv2.Trim();
            }
            else
            {
                cvv2 = "";
            }
            if (expiryDate != null)
            {
                expiryDate = expiryDate.Trim();
            }
            else
            {
                expiryDate = "";
            }

            if (modulus != null)
                publicKeyModulus = modulus;

            if (pubExpo != null)
                publicKeyExponent = pubExpo;

            String authData = String.Format("1Z{0}Z{1}Z{2}Z{3}", pan, pin, expiryDate, cvv2);
            string result = RsaEncryptWithPrivate(authData);
            return result;
        }


        public static string RsaEncryptWithPrivate(string clearText)
        {

            BigInteger Mod = new BigInteger(publicKeyModulus, 16);
            //static BigInteger Mod = new BigInteger(Encoding.UTF8.GetBytes(modulus));
            BigInteger PubExp = new BigInteger(publicKeyExponent, 16);

            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, Mod, PubExp);
            Pkcs1Encoding encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, pubParameters);
            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }


        private static String encryptPinBlock(String clearPinBlock, byte[] pinKey)
        {
            Debug.Assert(clearPinBlock != null, "Pin block cannot be null");
            Debug.Assert(clearPinBlock.Length <= 16, "Pin block cannot be more than 16 xters");
            byte[] randomBytes = new byte[1];
            RandomNumberGenerator sr = RNGCryptoServiceProvider.Create();
            sr.GetBytes(randomBytes);
            int randomDigit = (int)((randomBytes[0] * 10) / 128);
            randomDigit = Math.Abs(randomDigit);
            int pinpadlen = 16 - clearPinBlock.Length;
            for (int i = 0; i < pinpadlen; i++)
                clearPinBlock = clearPinBlock + randomDigit;

            byte[] encodedEncryptedPINBlockBytes = DESUtils.encrypt(clearPinBlock, pinKey);
            String encryptedPinBlock = Encoding.Default.GetString(encodedEncryptedPINBlockBytes);
            clearPinBlock = "0000000000000000";
            AppUtils.zeroise(encodedEncryptedPINBlockBytes);
            return encryptedPinBlock;
        }

        /***
         * Use when you have pin, cvv2, and expiry date
         * @param pin: card pin
         * @param cvv2: card cvv2
         * @param expiryDate: card expiry date
         * @param pinKey: pin Key
         * @return
         */
        public static String getEncryptedPinCvv2ExpiryDateBlock(string pin, string cvv2, string expiryDate, byte[] pinKey)
        {
            if (pin == null || string.Compare(pin, "", true) == 0)
                pin = "0000";
            if (cvv2 == null || string.Compare(cvv2, "", true) == 0)
                cvv2 = "000";
            if (expiryDate == null || string.Compare(expiryDate, "", true) == 0)
                expiryDate = "0000";

            String pinBlockString = pin + cvv2 + expiryDate;
            int pinBlockStringLen = pinBlockString.Length;
            String pinBlockLenLenString = Convert.ToString(pinBlockStringLen);
            int pinBlockLenLen = pinBlockLenLenString.Length;
            String clearPinBlock = Convert.ToString(pinBlockLenLen) + pinBlockStringLen + pinBlockString;
            //clearPinBlock = "00000000";
            return encryptPinBlock(clearPinBlock, pinKey);
        }

        /***
         * Use when you have pin, cvv2, but no expiry date
         * @param pin: card pin
         * @param cvv2: card cvv2
         * @param pinKey: pin Key
         * @return
         */
        public static String getEncryptedPinCvv2Block(String pin, String cvv2, byte[] pinKey)
        {
            return getEncryptedPinCvv2ExpiryDateBlock(pin, cvv2, "", pinKey);
        }


        /***
         * Use when you have pin and expiry date, but no cvv2
         * @param pin: card pin
         * @param expiryDate: card expiry date
         * @param pinKey: pin Key
         * @return
         */
        public static String getEncryptedPinExpiryDateBlock(String pin, String expiryDate, byte[] pinKey)
        {
            return getEncryptedPinCvv2ExpiryDateBlock(pin, "000", expiryDate, pinKey);
        }

        /***
         * Use when you have only pin
         * @param pin: card pin
         * @param pinKey: pin Key
         * @return
         */
        public static String getEncryptedPinBlock(String pin, byte[] pinKey)
        {
            return getEncryptedPinCvv2ExpiryDateBlock(pin, "", "", pinKey);
        }

        /***
         * Use when you have only expiryDate
         * @param expiryDate: card expiry date
         * @param pinKey: pin Key
         * @return
         */
        public static String getEncryptedExpiryDateBlock(String expiryDate, byte[] pinKey)
        {
            return getEncryptedPinCvv2ExpiryDateBlock("0000", "000", expiryDate, pinKey);
        }


        
        public static String getGenericSecure(string pan, string msisdn, string ttId, string amt, byte[] pinKey, byte[] macKey)
        {
            byte[] secureBytes = new byte[64];
            byte[] headerBytes = new byte[1];
            byte[] formatVersionBytes = new byte[1];
            byte[] macVersionBytes = new byte[1];
            byte[] pinDesKey = new byte[16];
            byte[] macDesKey = new byte[16];
            byte[] customerIdBytes = new byte[10];
            byte[] macBytes = new byte[4];
            byte[] otherHexBytes = new byte[14];
            byte[] footerBytes = new byte[1];

            headerBytes = AppUtils.hexConverter(Constants.SECURE_HEADER);
            formatVersionBytes = AppUtils.hexConverter(Constants.SECURE_FORMAT_VERSION);
            macVersionBytes = AppUtils.hexConverter(Constants.SECURE_MAC_VERSION);
            pinDesKey = pinKey;
            macDesKey = macKey;
            footerBytes = AppUtils.hexConverter(Constants.SECURE_FOOTER);

            Array.Copy(headerBytes, headerBytes.GetLowerBound(0), secureBytes, 0, 1);
            Array.Copy(formatVersionBytes, 0, secureBytes, 1, 1);
            Array.Copy(macVersionBytes, 0, secureBytes, 2, 1);
            Array.Copy(pinDesKey, 0, secureBytes, 3, 16);
            Array.Copy(macDesKey, 0, secureBytes, 19, 16);

            string customerIdLen = pan == null ? "" : pan.Length.ToString();
            string customerIdLenLen = customerIdLen.Length.ToString();
            string customerIdBlock = customerIdLenLen + customerIdLen + pan;
            int customerIdBlockLen = customerIdBlock.Length;
 
            int maxLen = 20;
            int pandiff = maxLen - customerIdBlockLen;
            for (int i = 0; i < pandiff; i++) 
            {
                customerIdBlock = customerIdBlock + "F";
            }
            customerIdBytes = AppUtils.hexConverter(customerIdBlock);
            Array.Copy(customerIdBytes, 0, secureBytes, 35, 10);

            string macData = getMacCipherText(msisdn, ttId, amt);
            string mac = MACUtils.getMacValueUsingHMAC(macData, pinKey);
            mac = mac.Substring(0, 8);
            macBytes = AppUtils.hexConverter(mac);
            Array.Copy(macBytes, 0, secureBytes, 45, 4);

            string otherHex = "0000000000000000000000000000";
            otherHexBytes = AppUtils.hexConverter(otherHex);
            Array.Copy(otherHexBytes, 0, secureBytes, 49, 14);

            Array.Copy(footerBytes, 0, secureBytes, 63, 1);
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in secureBytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
            String encrytedSecure = Encoding.Default.GetString(RSAUtils.rsaEncrypt(publicKeyModulus, publicKeyExponent, secureBytes));
            AppUtils.zeroise(secureBytes);

            return encrytedSecure;

        }



        private static string getSecure(byte[] secureBody, byte[] pinKey, byte[] macKey)
        {
            byte[] secureBytes = new byte[64];
            byte[] headerBytes = new byte[1];
            byte[] formatVersionBytes = new byte[1];
            byte[] macVersionBytes = new byte[1];
            byte[] pinDesKey = new byte[16];
            byte[] macDesKey = new byte[16];
            byte[] secureBodyBytes = new byte[28];
            byte[] footerBytes = new byte[1];

            headerBytes = AppUtils.hexConverter(Constants.SECURE_HEADER);
            formatVersionBytes = AppUtils.hexConverter(Constants.SECURE_FORMAT_VERSION);
            macVersionBytes = AppUtils.hexConverter(Constants.SECURE_MAC_VERSION);
            pinDesKey = pinKey;
            macDesKey = macKey;
            secureBodyBytes = secureBody;
            footerBytes = AppUtils.hexConverter(Constants.SECURE_FOOTER);

            Array.Copy(headerBytes, headerBytes.GetLowerBound(0), secureBytes, 0, 1);
            Array.Copy(formatVersionBytes, 0, secureBytes, 1, 1);
            Array.Copy(macVersionBytes, 0, secureBytes, 2, 1);
            Array.Copy(pinDesKey, 0, secureBytes, 3, 16);
            Array.Copy(macDesKey, 0, secureBytes, 19, 16);
            Array.Copy(secureBodyBytes, 0, secureBytes, 35, 28);
            Array.Copy(footerBytes, 0, secureBytes, 63, 1);
            String encrytedSecure = Encoding.Default.GetString(RSAUtils.rsaEncrypt(publicKeyModulus, publicKeyExponent, secureBytes));
            AppUtils.zeroise(secureBytes);

            return encrytedSecure;
        }

        /***
         * Use this function to calculate secure for CreatePaymentMethod transaction type.
         * @param pan: Payment Method's PAN
         * @param mac: Calculated MAC. Use MACUtils.getMAC().
         * @param pinKey: Generated Pin Key
         * @param macKey: Generated macKey
         * @return
         */
        public static String getCreatePaymentMethodSecure(string pan, string mac, byte[] pinKey, byte[] macKey)
        {

            byte[] panBytes = new byte[20];
            byte[] macBytes = Hex.Decode(mac);
            byte[] padBytes = AppUtils.hexConverter("FFFFFFFF");


            string panLen = Convert.ToString(pan.Length);
            int panLenLen = panLen.Length;
            string panBlock = Convert.ToString(panLenLen) + panLen + pan;
            string rightPadded = AppUtils.padRight(panBlock, 40, "F");
            panBytes = AppUtils.hexConverter(rightPadded);

            byte[] secureBodyBytes = new byte[28];
            Array.Copy(panBytes, 0, secureBodyBytes, 0, 20);
            Array.Copy(macBytes, 0, secureBodyBytes, 20, 4);
            Array.Copy(padBytes, 0, secureBodyBytes, 24, 4);

            string secure = getSecure(secureBodyBytes, pinKey, macKey);
            return secure;
        }

        /***
         * Use this method to generate secure for every other transaction type. (Generate Token, Balance Enquiry, Mini Statement)
         * @param subscriberId Subscriber mobile number
         * @param mac: Calculated MAC. Use MACUtils.getMAC().
         * @param pinKey: Generated Pin Key
         * @param macKey: Generated macKey
         * @return
         */
        public static String getSecure(string subscriberId, string mac, byte[] pinKey, byte[] macKey)
        {
            byte[] subscriberIdBytes = new byte[8];
            byte[] macBytes = Hex.Decode(mac);
            byte[] padBytes = AppUtils.hexConverter("FFFFFFFF");

            string paddedSubscriberId = AppUtils.padRight(subscriberId, 40, "0");
            subscriberIdBytes = AppUtils.hexConverter(paddedSubscriberId);

            byte[] secureBodyBytes = new byte[28];
            Array.Copy(subscriberIdBytes, 0, secureBodyBytes, 0, 20);
            Array.Copy(macBytes, 0, secureBodyBytes, 20, 4);
            Array.Copy(padBytes, 0, secureBodyBytes, 24, 4);

            string secure = getSecure(secureBodyBytes, pinKey, macKey);
            return secure;
        }

        public static String getPanSecure(string pan, string mac, byte[] pinKey, byte[] macKey)
        {
            byte[] subscriberIdBytes = new byte[8];
            byte[] macBytes = Hex.Decode(mac);
            byte[] padBytes = AppUtils.hexConverter("FFFFFFFF");

            string paddedPan = AppUtils.padRight(pan, 20, "0");
            subscriberIdBytes = AppUtils.hexConverter(paddedPan);

            byte[] secureBodyBytes = new byte[28];
            Array.Copy(subscriberIdBytes, 0, secureBodyBytes, 0, 10);
            Array.Copy(macBytes, 0, secureBodyBytes, 10, 4);
            Array.Copy(padBytes, 0, secureBodyBytes, 14, 14);

            string secure = getSecure(secureBodyBytes, pinKey, macKey);
            return secure;
        }



        public static string getMacCipherText(string subscriberId, string ttid, string amount = null, string phoneNumber = null, string customerId = null, string paymentItemCode = null)
        {
            string macData = "";

            if (!AppUtils.isNullOrEmpty(subscriberId))
                macData += subscriberId;

            macData += "default";

            if (!AppUtils.isNullOrEmpty(ttid))
                macData += ttid;

            if (!AppUtils.isNullOrEmpty(amount))
                macData += amount;

            if (!AppUtils.isNullOrEmpty(phoneNumber))
                macData += phoneNumber;

            if (!AppUtils.isNullOrEmpty(customerId))
                macData += customerId;

            if (!AppUtils.isNullOrEmpty(paymentItemCode))
                macData += paymentItemCode;

            return macData;
        }

        public static Dictionary<string, string> generateSecureData(Dictionary<string, string> options, Dictionary<string, string> pinData)
        {
            string pin = "0000";
            string cvv = "000";
            string expiry = "0000";
            Random rand = new Random();
            string ttId = rand.Next(999).ToString();
            string pan = "0000000000000000";
            string amt = "";
            string msisdn = "";
            string pubMod = publicKeyModulus;
            string pubExp = publicKeyExponent;
            
            if(options.ContainsKey("pan"))
            {
              options.TryGetValue("pan", out pan);
              pan = (pan == null || pan.Equals("")) ? "0000000000000000" : pan;
            }
            if(options.ContainsKey("ttId"))
            {
              options.TryGetValue("ttId", out ttId);
              ttId = (ttId == null || ttId.Equals("")) ? rand.Next(999).ToString() : ttId;
            }
            if (options.ContainsKey("amount"))
            {
              options.TryGetValue("amount", out amt);
              amt = (amt == null) ? "" : amt;
            }
            if (options.ContainsKey("mobile"))
            {
              options.TryGetValue("mobile", out msisdn);
              msisdn = (msisdn == null) ? "" : msisdn;
            }

            if (pinData.ContainsKey("pin"))
            {
              pinData.TryGetValue("pin", out pin);
              pin = (pin == null || pin.Equals("")) ? "0000" : pin;
            }
            if (pinData.ContainsKey("cvv"))
            {
              pinData.TryGetValue("cvv", out cvv);
              cvv = (cvv == null || cvv.Equals("")) ? "000" : cvv;
            }
            if(pinData.ContainsKey("expiry"))
            {
              pinData.TryGetValue("expiry", out expiry);
              expiry = (expiry == null || expiry.Equals("")) ? "0000" : expiry;
            }

            byte[] pinKey = DESUtils.generateKey();
    
            /*
            if(options.ContainsKey("publicKeyModulus"))
            {
                options.TryGetValue("publicKeyModulus", out pubMod);
                pubMod = (pubMod == null || pubMod.Equals("")) ? publicKeyModulus : pubMod;
            }
            if(options.ContainsKey("publicKeyExponent"))
            {
                options.TryGetValue("publicKeyExponent", out pubExp);
                pubExp = (pubExp == null || pubExp.Equals("")) ? publicKeyExponent : pubExp;
            }
            */
                        
            string secureData = getGenericSecure(pan, msisdn, ttId, amt, pinKey, pinKey);
            string pinBlock = getEncryptedPinCvv2ExpiryDateBlock(pin, cvv, expiry, pinKey);
            string macData = getMacCipherText(msisdn, ttId, amt);
            string mac = MACUtils.getMacValueUsingHMAC(macData, pinKey);
            
            Dictionary<string, string> secure = new Dictionary<string, string>();
            secure.Add("secureData", secureData);
            secure.Add("pinBlock", pinBlock);
            secure.Add("mac", mac);

            return secure;
        }

    }
}
