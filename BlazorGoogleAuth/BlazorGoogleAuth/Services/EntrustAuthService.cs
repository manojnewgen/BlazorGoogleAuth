using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
namespace BlazorGoogleAuth.Services
{

    public class EntrustAuthService
    {
        private readonly IConfiguration _configuration;

        public EntrustAuthService(IConfiguration configuration)
        {         
            _configuration = configuration;
        }

        public async Task<string> AuthenticateWithEntraID(string username, string password)
        {
            var clientId = _configuration["Authentication:ClientId"];
            var clientSecret = _configuration["Authentication:ClientSecret"];
            var tenantId = _configuration["Authentication:TenantId"];
            var request = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token");

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default"),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password)
            });

            request.Content = content;

            using (var client = new HttpClient())
            {
                var response = await client.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var tokenResponse = JsonConvert.DeserializeObject<OAuthTokenResponse>(responseContent);
                    return tokenResponse.AccessToken;
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    throw new Exception($"Error authenticating with Entra ID: {response.StatusCode}, {errorContent}");
                }
            }
        }

        public class OAuthTokenResponse
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }

            [JsonProperty("expires_in")]
            public int ExpiresIn { get; set; }

            [JsonProperty("token_type")]
            public string TokenType { get; set; }
        }

    }
}
