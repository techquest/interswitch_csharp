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

namespace Payment
{
    
    public class Interswitch
    {
        public string clientId;
        public string clientSecret;
        public string myAccessToken;
        public string environment;
        public string authData;

        public String getAuthdata(string pan, string pin, string expiryDate, string cvv)
        {            
            authData = Crypto.GetAuthData(pan,pin,expiryDate,cvv);
            return authData;
        }
        public String getAuthdata(string  mod, string pubExpo, string pan, string pin, string expiryDate, string cvv)
        {
             authData = Crypto.GetAuthData(mod,pubExpo, pan, pin, expiryDate, cvv);
             return authData;
        } 
        public String getToken()
        {
            Token accessToken = GetClientAccessToken(this.clientId,this.clientSecret).Result;            
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

        public virtual async Task<Token> GetClientAccessToken(String ClientId, String ClientSecret)
        {
            string url = String.Concat(environment,"/passport/oauth/token");
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
                //Token token = new Token()
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
        public virtual async Task<String> send(String uri, String httpMethod, object data)
        {
            try
            {
                string url = String.Concat("http://172.26.40.131:19081", uri);
                RestClient client = new RestClient(url);
                client.IgnoreResponseStatusCode = true;
                IRestResponse response = null;
                Config authConfig = new Config(httpMethod, url, clientId, clientSecret, myAccessToken, "", "");
                String purchaseResponse;
                var paymentRequests = new RestRequest(url, HttpMethod.Post);
                paymentRequests.AddHeader(Constants.Contenttype, "application/json");
                paymentRequests.AddHeader("Signature", authConfig.Signature);
                paymentRequests.AddHeader("SignatureMethod", "SHA1");
                paymentRequests.AddHeader("Timestamp", authConfig.TimeStamp);
                paymentRequests.AddHeader("Nonce", authConfig.Nonce);
                paymentRequests.AddHeader("Authorization", authConfig.Authorization);                
                paymentRequests.AddJsonBody(data);
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                JsonDeserializer deserial = new JsonDeserializer();
                response = await client.Execute(paymentRequests);
                HttpStatusCode httpStatusCode = response.StatusCode;
                int numericStatusCode = (int)httpStatusCode;
                if (numericStatusCode == 200 || numericStatusCode == 202)
                {
                    return System.Text.Encoding.UTF8.GetString(response.RawBytes);
                }
                else
                {
                    return System.Text.Encoding.UTF8.GetString(response.RawBytes);
                }
                return System.Text.Encoding.UTF8.GetString(response.RawBytes);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            
        }
        public virtual async Task<String> send(String uri, String httpMethod, object data, String token)
        {
            try
            {
                string url = String.Concat("http://172.26.40.131:19081", uri);
                RestClient client = new RestClient(url);
                client.IgnoreResponseStatusCode = true;
                IRestResponse response = null;
                Config authConfig = new Config(httpMethod, url, clientId, clientSecret, token, "", "");
                String purchaseResponse;
                var paymentRequests = new RestRequest(url, HttpMethod.Post);
                paymentRequests.AddHeader(Constants.Contenttype, "application/json");
                paymentRequests.AddHeader("Signature", authConfig.Signature);
                paymentRequests.AddHeader("SignatureMethod", "SHA1");
                paymentRequests.AddHeader("Timestamp", authConfig.TimeStamp);
                paymentRequests.AddHeader("Nonce", authConfig.Nonce);
                paymentRequests.AddHeader("Authorization", authConfig.Authorization);                
                paymentRequests.AddJsonBody(data);
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                JsonDeserializer deserial = new JsonDeserializer();
                response = await client.Execute(paymentRequests);
                HttpStatusCode httpStatusCode = response.StatusCode;
                int numericStatusCode = (int)httpStatusCode;
                if (numericStatusCode == 200 || numericStatusCode == 202)
                {
                    return System.Text.Encoding.UTF8.GetString(response.RawBytes);
                }
                else
                {
                    return System.Text.Encoding.UTF8.GetString(response.RawBytes);
                }
                return System.Text.Encoding.UTF8.GetString(response.RawBytes);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            
        }
        public static String setAuthorization(String clientId, String clientSecret)
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
        public void init(String clientId, String clientSecret)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.environment = "https://sandbox.interswitchng.com";
            this.myAccessToken = this.getToken();
        }
        public void init(String clientId, String clientSecret, String environment)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.environment = environment;
            this.myAccessToken = this.getToken();
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
