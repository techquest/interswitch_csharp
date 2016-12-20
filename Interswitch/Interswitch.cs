using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using RestSharp.Portable;
using RestSharp.Portable.Deserializers;
using System.Net;
using System.Net.Http;

namespace Interswitch
{
    
    public class Interswitch
    {
        public string clientId;
        public string clientSecret;
        public string myAccessToken;
        public string environment;
        public string authData;
        public static string SANDBOX = "SANDBOX";
        public static string PRODUCTION = "PRODUCTION";
        public static string HTTP_CODE = "CODE";
        public static string HTTP_RESPONSE = "RESPONSE";

        public Interswitch(String clientId, String clientSecret, String environment = null)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.environment = environment;
            //this.myAccessToken = this.getToken();
        }

        /*
        public String getToken()
        {
            Token accessToken = GetClientAccessToken(this.clientId, this.clientSecret).Result;            
            return accessToken.access_token;
        }
        public long getTimeStamp()
        {
            Config config = new Config();
            return config.GetTimeStamp();
        }
        public String getSignature()
        {
            Config config = new Config();
            return config.GetSignature();
        }
        public String getNonce()
        {
            Config config = new Config();
            return config.GetNonce();
        }
        */

        public virtual async Task<Token> GetClientAccessToken(String ClientId, String ClientSecret)
        {
            string url = Constants.SANDBOX_URL;
            if(PRODUCTION.Equals(environment, StringComparison.OrdinalIgnoreCase))
            {
                url = Constants.PRODUCTION_URL;
            }

            url = String.Concat(url, "/passport/oauth/token");
            RestClient client = new RestClient(url);
            client.IgnoreResponseStatusCode = true;

            var request = new RestRequest(url, HttpMethod.Post);
            request.AddHeader(Constants.Contenttype, Constants.ContentType);
            request.AddHeader(Constants.Authorization, setAuthorization(ClientId, ClientSecret));
            request.AddParameter("grant_type", "client_credentials", ParameterType.GetOrPost);
            request.AddParameter("Scope", "profile", ParameterType.GetOrPost);

            JsonDeserializer deserial = new JsonDeserializer();
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            IRestResponse response = await client.Execute(request);

            HttpStatusCode httpStatusCode = response.StatusCode;
            int numericStatusCode = (int)httpStatusCode;
            Token passportResponse = new Token(); ;
            if (numericStatusCode == 200)
            {
                passportResponse = deserial.Deserialize<Token>(response);
                passportResponse.setAccessToken(passportResponse.access_token);
            }
            else if (response.ContentType == "text/html" || (numericStatusCode == 401 || numericStatusCode == 404 || numericStatusCode == 502 || numericStatusCode == 504))
            {
                passportResponse.ErrorCode = numericStatusCode.ToString();
                passportResponse.ErrorMessage = response.StatusDescription;
            }
            else
            {
                var errorResponse = deserial.Deserialize<ErrorResponse>(response);
                passportResponse.ErrorCode = errorResponse.error.code;
                passportResponse.ErrorMessage = errorResponse.error.message;
            }            
            return passportResponse;
        }


        public Dictionary<string, string> Send(String uri, String httpMethod, object data = null, Dictionary<string, string> headers = null, String signedParameters = null)
        {
            try
            {
                Token token = GetClientAccessToken(this.clientId, this.clientSecret).Result;
                var accessToken = token.access_token;
                return SendWithAccessToken(uri, httpMethod, accessToken, data, headers, signedParameters);

            }
            catch (Exception ex)
            {
                throw ex;
            }            
        }


        public Dictionary<string, string> SendWithAccessToken(String uri, String httpMethod, String accessToken, object data = null, Dictionary<string, string> headers = null, String signedParameters = null)
        {
            try
            {
                string url = getUrl(environment);
                url = String.Concat(url, uri);

                RestClient client = new RestClient(url);
                client.IgnoreResponseStatusCode = true;
                IRestResponse response = null;
                Config authConfig = new Config(httpMethod, url, this.clientId, this.clientSecret, accessToken, signedParameters);

                HttpMethod httpMethodObj = (httpMethod == null || httpMethod.Equals("")) ? HttpMethod.Get : new HttpMethod(httpMethod);
                
                var paymentRequests = new RestRequest(url, httpMethodObj);
                paymentRequests.AddHeader(Constants.Contenttype, "application/json");
                paymentRequests.AddHeader("Signature", authConfig.Signature);
                paymentRequests.AddHeader("SignatureMethod", "SHA1");
                paymentRequests.AddHeader("Timestamp", authConfig.TimeStamp);
                paymentRequests.AddHeader("Nonce", authConfig.Nonce);
                paymentRequests.AddHeader("Authorization", authConfig.Authorization);
                if (headers != null && headers.Count() > 0)
                {
                    foreach(KeyValuePair<string, string> entry in headers)
                    {
                        paymentRequests.AddHeader(entry.Key, entry.Value);
                    }                    
                }

                if(data != null)
                    paymentRequests.AddJsonBody(data);

                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                JsonDeserializer deserial = new JsonDeserializer();
                //try
                //{
                    response = client.Execute(paymentRequests).Result;
                /*
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.StackTrace.ToString());
                    throw ex;
                }
                */

                HttpStatusCode httpStatusCode = response.StatusCode;
                int numericStatusCode = (int)httpStatusCode;
                Dictionary<string, string> responseObject = new Dictionary<string, string>();
                responseObject.Add(HTTP_CODE, numericStatusCode.ToString());
                responseObject.Add(HTTP_RESPONSE, System.Text.Encoding.UTF8.GetString(response.RawBytes));

                return responseObject;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            
        }

        public String GetAuthData(string pan, string expiryDate, string cvv, string pin, string mod = null, string pubExpo = null)
        {
            authData = SecurityUtils.GetAuthData(pan, pin, expiryDate, cvv, mod, pubExpo);
            return authData;
        }

        public Dictionary<string, string> GetSecureData(string pan, string expDate, string cvv, string pin, string amt = null, string msisdn = null, string ttid = null)
        {
            Dictionary<string, string> options = new Dictionary<string, string>();
            Dictionary<string, string> pinData = new Dictionary<string, string>();

            options.Add("pan", pan);
            options.Add("ttId", ttid);
            options.Add("amount", amt);
            options.Add("mobile", msisdn);

            pinData.Add("pin", pin);
            pinData.Add("cvv", cvv);
            pinData.Add("expiry", expDate);
            
            Dictionary<string, string> secure = SecurityUtils.generateSecureData(options, pinData);
                        
            return secure;
        } 




        private static String setAuthorization(String clientId, String clientSecret)
        {
            try
            {
                String Auth;
                byte[] bytes;
                bytes = Encoding.UTF8.GetBytes(String.Format("{0}:{1}", clientId, clientSecret));
                Auth = Convert.ToBase64String(bytes);
                return String.Concat("Basic ", Auth);
            }
            catch (Exception e)
            {
                throw new Exception("Unable to encode parameters, Please contact connect@interswitchng.com. for assistance.", e);
            }
        }

        private static String getUrl(String environment)
        {
            string url = Constants.SANDBOX_URL;
            if (PRODUCTION.Equals(environment, StringComparison.OrdinalIgnoreCase))
            {
                url = Constants.PRODUCTION_URL;
            }
            return url;
        }
        
    }
        
    public class Token
    {
        
        public string access_token { get; set; }       
        public string token_type { get; set; }       
        public string refresh_token { get; set; }        
        public string expires_in { get; set; }        
        public string scope { get; set; }        
        public string requestor_id { get; set; }        
        public string merchant_code { get; set; }        
        public string email { get; set; }        
        public string firstName { get; set; }        
        public string lastName { get; set; }
        public string payable_id { get; set; }
        public string payment_code { get; set; }
        public string jti { get; set; }
        public string ErrorCode { get; set; }
        public string ErrorMessage { get; set; }       
        public void setAccessToken(string token)
        {
            this.access_token = token;
        }
    }
    public class Error1
    {
        public string code { get; set; }
        public string message { get; set; }
    }

    public class Error2
    {
        public string code { get; set; }
        public string message { get; set; }
    }

    public class ErrorResponse
    {
        public List<Error1> errors { get; set; }
        public Error2 error { get; set; }
        public string transactionRef { get; set; }
    }   
}
