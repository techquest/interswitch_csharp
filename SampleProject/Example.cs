using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Interswitch;
using System.Web.Script.Serialization;
using RestSharp.Portable;
using RestSharp.Portable.Deserializers;
using System.IdentityModel.Tokens;

namespace SampleProject
{
    public class Example
    {
        static string clientId = "IKIA9614B82064D632E9B6418DF358A6A4AEA84D7218";
        static string clientSecret = "XCTiBtLy1G9chAnyg0z3BcaFK4cVpwDg/GTw2EmjTZ8=";
        static void Main(string[] args)
        {
            Interswitch.Interswitch interswitch = new Interswitch.Interswitch(clientId, clientSecret);

            // Payment
            bool hasRespCode = false;
            bool hasRespMsg = false;
            string httpRespCode = "400";
            string httpRespMsg = "Failed";
            Random rand = new Random();

            string amt = "35000";
            string currency = "NGN";
            string custId = "customer@myshop.com";
            var id = rand.Next(99999999);

            var pan = "6280511000000095";
            var expDate = "5004";
            var cvv = "111";
            var pin = "1111";
            var otpPan = "5061020000000000011";
            var otpExpDate = "1801";
            var otpCvv = "350";
            var otpPin = "1111";

            string expDate2 = "1909";
            string cvv2 = "123";
            string pin2 = "1234";
            string amt2 = "500000";
            string tranType = "Withdrawal";
            string pwmChannel = "ATM";
            string tokenLifeInMin = "90";
            string onetimepin = "1234";
            string fep = "WEMA";


            String authdata = interswitch.GetAuthData("5060990580000217499", "2004", "111", "1111");
            var validateReqRef =  rand.Next(99999999);

            object validateReq = new{
               transactionRef = validateReqRef,
               authData = authdata
            };
            var validationResp = interswitch.Send("/api/v2/purchases/validations", "POST", validateReq);
            hasRespCode = validationResp.TryGetValue("CODE", out httpRespCode);
            hasRespMsg = validationResp.TryGetValue("RESPONSE", out httpRespMsg);
            Console.WriteLine("Validation HTTP Code: " + httpRespCode);
            Console.WriteLine("Validation HTTP Data: " + httpRespMsg);
            
            var transactionRef =  rand.Next(99999999);
             object paymentRequest = new
                {
                    customerId = "1234567890",
                    amount = "100",
                    transactionRef = transactionRef,
                    currency = "NGN",
                    authData = authdata
                };
             
             Dictionary<string, string> paymentResp = interswitch.Send("/api/v2/purchases", "POST", paymentRequest);
             hasRespCode = paymentResp.TryGetValue("CODE", out httpRespCode);
             hasRespMsg = paymentResp.TryGetValue("RESPONSE", out httpRespMsg);
             Console.WriteLine("Payment HTTP Code: " + httpRespCode);
             Console.WriteLine("Payment HTTP Data: " + httpRespMsg);
             

             if(hasRespCode && hasRespMsg && (httpRespCode == "201" || httpRespCode == "202"))
             {
                 Response response = new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Response>(httpRespMsg);
                 object verifyOTPReq = new {
                     paymentId = response.paymentId,
                     otp = "123456"
                 };
                 var otpResp = interswitch.Send("api/v2/purchases/otps/auths", "POST", verifyOTPReq);
                 hasRespCode = otpResp.TryGetValue("CODE", out httpRespCode);
                 hasRespMsg = otpResp.TryGetValue("RESPONSE", out httpRespMsg);
                 Console.WriteLine("Payment OTP HTTP Code: " + httpRespCode);
                 Console.WriteLine("Payment OTP HTTP Data: " + httpRespMsg);
             }

              Dictionary<string, string> headers = new Dictionary<string,string>();
              headers.Add("amount", "100");
              headers.Add("transactionRef", transactionRef.ToString());
             
             var statusResp = interswitch.Send("/api/v2/purchases", "GET", null, headers);
             hasRespCode = statusResp.TryGetValue("CODE", out httpRespCode);
             hasRespMsg = statusResp.TryGetValue("RESPONSE", out httpRespMsg);
             Console.WriteLine("Payment Status HTTP Code: " + httpRespCode);
             Console.WriteLine("Payment Status HTTP Data: " + httpRespMsg);
            


            // Paycode
            var tokenHandler = new JwtSecurityTokenHandler();
            string accessToken = "eyJhbGciOiJSUzI1NiJ9.eyJsYXN0TmFtZSI6IkpBTSIsIm1lcmNoYW50X2NvZGUiOiJNWDE4NyIsInByb2R1Y3Rpb25fcGF5bWVudF9jb2RlIjoiMDQyNTk0MTMwMjQ2IiwidXNlcl9uYW1lIjoiYXBpLWphbUBpbnRlcnN3aXRjaGdyb3VwLmNvbSIsInJlcXVlc3Rvcl9pZCI6IjAwMTE3NjE0OTkyIiwibW9iaWxlTm8iOiIyMzQ4MDk4Njc0NTIzIiwicGF5YWJsZV9pZCI6IjIzMjQiLCJjbGllbnRfaWQiOiJJS0lBOTYxNEI4MjA2NEQ2MzJFOUI2NDE4REYzNThBNkE0QUVBODRENzIxOCIsImZpcnN0TmFtZSI6IkFQSSIsImVtYWlsVmVyaWZpZWQiOnRydWUsImF1ZCI6WyJjYXJkbGVzcy1zZXJ2aWNlIiwiaXN3LWNvbGxlY3Rpb25zIiwiaXN3LXBheW1lbnRnYXRld2F5IiwicGFzc3BvcnQiLCJ2YXVsdCJdLCJzY29wZSI6WyJwcm9maWxlIl0sImV4cCI6MTQ4MjI4MDkwNCwibW9iaWxlTm9WZXJpZmllZCI6dHJ1ZSwianRpIjoiYmVhNDU0YTAtMDVkOS00MWI3LWJmMDctMjQ1NDdlZTFkMzE3IiwiZW1haWwiOiJhcGktamFtQGludGVyc3dpdGNoZ3JvdXAuY29tIiwicGFzc3BvcnRJZCI6IjYxMWRmNzZhLWI0MzItNDczNy05YzY0LTc2MDdkYWRjYWNhZCIsInBheW1lbnRfY29kZSI6IjA1MTQxOTgxNTQ2ODUifQ.VHkD5H2i1Yjq8Oan1DmbokrQXGhfrYG_EWpkh3fUjhCKW_6YsM8z4Z_2XlVeUNpSSQjd8T7oARX_J06Gx4Vc0NT6Quc7eAY776VODiTfdZ98IADX6S8Go9VpARfZf-on_LbtVZXyfje3-HO1P9C9LyhPi1KexdBfYuE1GXKLIBdebXvvX0hLU81D_NE5yoDG8XDQqfiW4OPDyaCc8Mg7a6qk6HoCcxZSEOy6Flv2TAZdbNRpUMUBqYxOcZ8I6hdjN06AfBR3tLIja9oQA7IlWGkWxEp60R6pynFBouhY8XksX2vHU0EmoIv-3qVosS-ypEwKwEGAr7BwpFqS_RbahQ";
            JwtSecurityToken secToken = (JwtSecurityToken) tokenHandler.ReadToken(accessToken);
            var payload = secToken.Payload;
            if (payload.ContainsKey("mobileNo"))
            {
                var getPaymentMethodResp = interswitch.SendWithAccessToken("/api/v1/ewallet/instruments", "GET", accessToken);
                hasRespCode = getPaymentMethodResp.TryGetValue("CODE", out httpRespCode);
                hasRespMsg = getPaymentMethodResp.TryGetValue("RESPONSE", out httpRespMsg);
                Console.WriteLine("Get Payment Methods HTTP Code: " + httpRespCode);
                Console.WriteLine("Get Payment Methods HTTP Data: " + httpRespMsg);
                if (hasRespCode && hasRespMsg && (httpRespCode == "200" || httpRespCode == "201" || httpRespCode == "202"))
                {
                    Response response = new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Response>(httpRespMsg);
                    if (response.paymentMethods != null && response.paymentMethods.Length > 0)
                    {
                        object msisdnObj = "";
                        payload.TryGetValue("mobileNo", out msisdnObj);
                        string msisdn = msisdnObj.ToString();
                        
                        var ttid = rand.Next(9999);
                        string token = response.paymentMethods[1].token;
                        Dictionary<string, string> secure = interswitch.GetSecureData(null, expDate2, cvv2, pin2, null, msisdn, ttid.ToString());
                        string secureData;
                        string pinData;
                        string mac;
                        bool hasSecureData = secure.TryGetValue("secureData", out secureData);
                        bool hasPinBlock = secure.TryGetValue("pinBlock", out pinData);
                        bool hasMac = secure.TryGetValue("mac", out mac);
                        Dictionary<string, string> httpHeader = new Dictionary<string,string>();
                        httpHeader.Add("frontendpartnerid", "WEMA");

                        var req = new {
                            amount = "500000",
                            ttid = ttid,
                            transactionType = "Withdrawal",
                            paymentMethodIdentifier = token,
                            payWithMobileChannel = "ATM",
                            tokenLifeTimeInMinutes = "90",
                            oneTimePin = "1234",
                            pinData = pinData,
                            secure = secureData,
                            macData = mac
                        };

                        var paycodeResp = interswitch.SendWithAccessToken("/api/v1/pwm/subscribers/" + msisdn + "/tokens", "POST", accessToken, req, httpHeader);
                        hasRespCode = paycodeResp.TryGetValue("CODE", out httpRespCode);
                        hasRespMsg = paycodeResp.TryGetValue("RESPONSE", out httpRespMsg);
                        Console.WriteLine("Generate Paycode HTTP Code: " + httpRespCode);
                        Console.WriteLine("Generate Paycode HTTP Data: " + httpRespMsg);
                    }
                }
            }
            

            Console.ReadKey();
        }
                
    }

     public class Response
    {
        public string paymentId { get; set; }
        public string transactionRef { get; set; }
        public PaymentMethod[] paymentMethods { get; set; }
    }

     public class PaymentMethod
     {
         public string paymentMethodTypeCode { get; set; }
         public string paymentMethodCode { get; set; }
         public string cardProduct { get; set; }
         public string panLast4Digits { get; set; }
         public string token { get; set; }
     }
}
