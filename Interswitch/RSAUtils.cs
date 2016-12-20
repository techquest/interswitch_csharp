using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Math;

namespace Interswitch
{
    public class RSAUtils
    {

        public static byte[] rsaEncrypt(String publicKeyModulus, String publicKeyExponent, byte[] cipher)
        {
            RsaEngine engine = new RsaEngine();
            RsaKeyParameters publicKeyParameters = getPublicKey(publicKeyModulus, publicKeyExponent);
            engine.Init(true, publicKeyParameters);
            byte[] encryptedSecureBytes = engine.ProcessBlock(cipher, 0, cipher.Length);
            byte[] encodedEncryptedSecureBytes = Hex.Encode(encryptedSecureBytes);
            return encodedEncryptedSecureBytes;
        }


        public static RsaKeyParameters getPublicKey(String modulus, String exponent)
        {
            var modulusByte = new BigInteger(Hex.Decode(modulus));
            var exponentByte = new BigInteger(Hex.Decode(exponent));
            var pkParameters = new RsaKeyParameters(false, modulusByte, exponentByte);
            return pkParameters;
        }
    }
}