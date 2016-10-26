using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Payment;
using System.Web.Script.Serialization;
namespace SampleProject
{
    public class Example
    {
        static string clientId = "IKIAF8F70479A6902D4BFF4E443EBF15D1D6CB19E232";
        static string  clientSecret = "ugsmiXPXOOvks9MR7+IFHSQSdk8ZzvwQMGvd0GJva30=";
        static void Main(string[] args)
        {
            Interswitch interswitch = new Interswitch();
            interswitch.init(clientId, clientSecret, "https://qa.interswitchng.com");
            string mod = "9C7B3BA621A26C4B02F48CFC07EF6EE0AED8E12B4BD11C5CC0ABF80D5206BE69E1891E60FC88E2D565E2FABE4D0CF630E318A6C721C3DED718D0C530CDF050387AD0A30A336899BBDA877D0EC7C7C3FFE693988BFAE0FFBAB71B25468C7814924F022CB5FDA36E0D2C30A7161FA1C6FB5FBD7D05ADBEF7E68D48F8B6C5F511827C4B1C5ED15B6F20555AFFC4D0857EF7AB2B5C18BA22BEA5D3A79BD1834BADB5878D8C7A4B19DA20C1F62340B1F7FBF01D2F2E97C9714A9DF376AC0EA58072B2B77AEB7872B54A89667519DE44D0FC73540BEEAEC4CB778A45EEBFBEFE2D817A8A8319B2BC6D9FA714F5289EC7C0DBC43496D71CF2A642CB679B0FC4072FD2CF";
            string pubExponent = "010001";
            String authdata = interswitch.getAuthdata("5060990580000217499","1111","2004","111");
            String token = interswitch.getToken();
            String authdata2 = interswitch.getAuthdata(mod,pubExponent,"5060990580000217499", "1111", "2004", "111");

            Console.WriteLine("*******************************");
            Console.WriteLine("Auth Data ");
            Console.WriteLine(authdata);
            Console.WriteLine("*******************************");
            Console.WriteLine("*******************************");
            Console.WriteLine("Auth Data 2 here with same credentials");
            Console.WriteLine(authdata);
            Console.WriteLine("*******************************");
            Random rand = new Random();
            Console.WriteLine(rand.Next(9999910));
            Console.WriteLine("****************************");
            Console.WriteLine("First overload method started ....");
             object paymentRequest =new
                {
                    customerId = "1234567890",
                    amount = "100",
                    transactionRef = rand.Next(99999999),
                    currency = "NGN",
                    authData = authdata
                };
             String response = interswitch.send("/api/v2/purchases", "POST", paymentRequest).Result;
             Console.WriteLine(response);
             Console.WriteLine("First overload method done ....");
             Console.WriteLine("****************************");
             Console.WriteLine("****************************");
             Console.WriteLine("Second overload method started ....");
             object paymentRequest2 = new
             {
                 customerId = "1234567890",
                 amount = "100",
                 transactionRef = rand.Next(99999999),
                 currency = "NGN",
                 authData = authdata
             };
             
             String response2 = interswitch.send("/api/v2/purchases", "POST", paymentRequest2,token).Result;
            Console.WriteLine(response2);
            Console.WriteLine("Second overload method done ....");
            Console.WriteLine("****************************");
            Console.ReadKey();
        }
                
    }
}
