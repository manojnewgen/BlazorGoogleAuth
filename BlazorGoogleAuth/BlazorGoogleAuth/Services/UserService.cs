using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using BlazorServerApp.Data;
using Microsoft.AspNetCore.Components.Authorization;
using BlazorGoogleAuth.Components.Account;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using BlazorGoogleAuth.Data;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authorization;
using BlazorGoogleAuth.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using BlazorGoogleAuth.Services;

namespace BlazorServerApp.Services
{
    public class UserService : IUserService
    {
        private readonly HttpClient _httpClient;
        private readonly AppSettings _appSettings;
        private readonly AuthenticationStateProvider _authStateProvider;
        private readonly IAuthorizationService _authorizationService;
        private readonly HybridAuthState _hybridAuthState;
        private readonly EntrustAuthService _entrustAuthService;
        private readonly ILogger<UserService> _logger;
        private readonly HybridAuthService _hybridAuthService;


        public UserService(HttpClient httpClient, IOptions<AppSettings> appSettings, AuthenticationStateProvider authStateProvider, IAuthorizationService authorizationService, HybridAuthState hybridAuthState, EntrustAuthService entrustAuthService, ILogger<UserService> logger, HybridAuthService hybridAuthService)
        {
            _httpClient = httpClient;
            _appSettings = appSettings.Value;
            _httpClient.BaseAddress = new Uri(_appSettings.BaseAddress);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "BlazorServer");
            _authStateProvider = authStateProvider;
            _authorizationService = authorizationService;
            _hybridAuthState = hybridAuthState;
            _entrustAuthService = entrustAuthService;
            _logger = logger;
            _hybridAuthService=hybridAuthService;


        }

        public async Task<string> LoginAsync(User user)
        {
            user.username = "manoj";
            var serializedUser = JsonConvert.SerializeObject(user);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "api/Auth/authenticate-custom")
            {
                Content = new StringContent(serializedUser)
            };
            requestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await _httpClient.SendAsync(requestMessage);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject authResult = JObject.Parse(responseBody);
                string token = (string)authResult["token"];
                
              //  _hybridAuthState.SetAuthenticationState(isAuthenticated: true, new string[] { "Admin", "Dev" });
                return token;
            }
            else
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var errorMessage = $"API call failed with status code: {response.StatusCode}, response: {responseBody}";
                // Log the error message
                Console.WriteLine(errorMessage);
                throw new Exception(errorMessage);
            }
        }

        public async Task<bool> AuthenticateWithEntrust(string username, string password)
        {
            // Call the EntrustAuthService to authenticate with Entrust ID
            var accessToken = await _entrustAuthService.AuthenticateWithEntraID(username, password);
           // var isAuthenticated = false;

            if (!string.IsNullOrEmpty(accessToken))
            {
               // return accessToken;
                _hybridAuthService.SetAccessToken(accessToken);
                _hybridAuthService.SetAuthenticationState(isAuthenticated: true, new string[] { "Admin", "Dev" });
                return true;
            }
            else
            {
                _logger.LogWarning("Entrust ID authentication failed.");
            }

            return false;
        }
       

        public async Task<User> RegisterUserAsync(User user)
        {
            user.Password = (user.Password);
            string serializedUser = JsonConvert.SerializeObject(user);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "Users/RegisterUser");
            requestMessage.Content = new StringContent(serializedUser);

            requestMessage.Content.Headers.ContentType
                = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await _httpClient.SendAsync(requestMessage);

            var responseStatusCode = response.StatusCode;
            var responseBody = await response.Content.ReadAsStringAsync();

            var returnedUser = JsonConvert.DeserializeObject<User>(responseBody);

            return returnedUser;
        }

        public async Task<User> GetUserByAccessTokenAsync(string accessToken)
        {
            string serializedRefreshRequest = JsonConvert.SerializeObject(accessToken);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "Users/GetUserByAccessToken");
            requestMessage.Content = new StringContent(serializedRefreshRequest);

            requestMessage.Content.Headers.ContentType
                = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await _httpClient.SendAsync(requestMessage);

            var responseStatusCode = response.StatusCode;
            var responseBody = await response.Content.ReadAsStringAsync();

            var returnedUser = JsonConvert.DeserializeObject<User>(responseBody);

            return returnedUser;
        }

    }
}
