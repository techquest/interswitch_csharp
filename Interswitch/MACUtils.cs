using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;

namespace Interswitch
{
    public class MACUtils
    {
        public static String getMacValue(String macCipherText, byte[] macKey)
        {
            byte[] macBytes = new byte[4];

            CbcBlockCipherMac cipher = new CbcBlockCipherMac(new DesEdeEngine());
            DesEdeParameters keyParameters = new DesEdeParameters(macKey);
            DesEdeEngine engine = new DesEdeEngine();
            engine.Init(true, keyParameters);
            cipher.Init(keyParameters);
            byte[] macDataBytes = Encoding.UTF8.GetBytes(macCipherText);
            cipher.BlockUpdate(macDataBytes, 0, macCipherText.Length);
            cipher.DoFinal(macBytes, 0);
            byte[] encodedMacBytes = Hex.Encode(macBytes);
            String mac = Encoding.Default.GetString(encodedMacBytes);
            return mac;
        }


        public static String getMacValueUsingHMAC(String macCipherText, byte[] macKey)
        {
            //byte[] macBytes = new byte[4];
            byte[] macDataBytes = Encoding.UTF8.GetBytes(macCipherText);

            HMACSHA256 hasher = new HMACSHA256(macKey);
            byte[] macBytesTmp = hasher.ComputeHash(macDataBytes);
            //Array.Copy(macBytesTmp, 0, macBytes, 0, 4);

            byte[] encodedMacBytes = Hex.Encode(macBytesTmp);
            //byte[] encodedMacBytes = Hex.Encode(macBytes);
            String mac = Encoding.Default.GetString(encodedMacBytes);
            return mac;

        }
   
    }
}