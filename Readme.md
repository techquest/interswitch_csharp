```c#

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Interswitch;
using System.Web.Script.Serialization;

static string clientId = "IKIA9614B82064D632E9B6418DF358A6A4AEA84D7218"; // Get your Client ID from https://developer.interswitchng.com
static string clientSecret = "XCTiBtLy1G9chAnyg0z3BcaFK4cVpwDg/GTw2EmjTZ8="; // Get your Client Secret from https://developer.interswitchng.com
static string ENV = "SANDBOX"; // or PRODUCTION
Interswitch.Interswitch interswitch = new Interswitch.Interswitch(clientId, clientSecret, ENV);

object requestData = new{
   data1 = data1
};
			
response = interswitch.Send("/api/v2/....", "POST", validateReq);
hasRespCode = response.TryGetValue("CODE", out httpRespCode);
hasRespMsg = response.TryGetValue("RESPONSE", out httpRespMsg);
Console.WriteLine("HTTP Code: " + httpRespCode);
Console.WriteLine("HTTP Data: " + httpRespMsg);
```

## Features

  * Sends request to Interswitch API
  * Calculates Interswitch Security Header
  * Packages Interswitch Sensitive Data (Card, PIN, CVV, Exp Date)
  * Generates PIN Block for Interswitch transactions
  * Generate MAC for Interswitch transactions
  
