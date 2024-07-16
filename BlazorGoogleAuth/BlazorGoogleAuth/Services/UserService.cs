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

namespace BlazorServerApp.Services
{
    public class UserService : IUserService
    {
        private readonly HttpClient _httpClient;
        private readonly AppSettings _appSettings;
        private readonly AuthenticationStateProvider _authStateProvider;
        private readonly IAuthorizationService _authorizationService;

        public UserService(HttpClient httpClient, IOptions<AppSettings> appSettings, AuthenticationStateProvider authStateProvider, IAuthorizationService authorizationService)
        {
            _httpClient = httpClient;
            _appSettings = appSettings.Value;
            _httpClient.BaseAddress = new Uri(_appSettings.BaseAddress);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "BlazorServer");
            _authStateProvider = authStateProvider;
            _authorizationService = authorizationService;
        }

        public async Task<AuthorizationResult> LoginAsync(User user)
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
               // await UpdateAuthenticationState(token);
                var claimsPrincipal = await GetClaimsPrincipalAsync();
                var authservice= await _authorizationService.AuthorizeAsync(claimsPrincipal, "Admin");
               
                return authservice;
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

        private async Task UpdateAuthenticationState(string token)
        {
            // Use the PersistingRevalidatingAuthenticationStateProvider to update authentication state
            var authStateProvider = _authStateProvider as PersistingRevalidatingAuthenticationStateProvider<ApplicationUser>;
            if (authStateProvider != null)
            {
                var handler = new JwtSecurityTokenHandler();
                var tokenS = handler.ReadToken(token) as JwtSecurityToken;

                var claims = tokenS.Claims;
                var identity = new ClaimsIdentity(claims, "apiauth");
                var user = new ClaimsPrincipal(identity);



                await authStateProvider.UpdateAuthenticationStateAsync(new AuthenticationState(user));
            }
            else
            {
                throw new InvalidOperationException("AuthenticationStateProvider is not of type PersistingRevalidatingAuthenticationStateProvider.");
            }
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

        private async Task<ClaimsPrincipal> GetClaimsPrincipalAsync()
        {
            var authenticationState = await _authStateProvider.GetAuthenticationStateAsync();
            var claimsPrincipal = authenticationState.User;
            var claimsIdentity = claimsPrincipal.Identities.First();

            //if (!_webHostEnvironment.IsProduction() && !string.IsNullOrEmpty(_profileProvider?.ConfigurationOverrides?.OktaGroup)
            //    && AuthConstants.DebugOktaGroupQueryMap.ContainsKey(_profileProvider.ConfigurationOverrides.OktaGroup))
            //{
            //    claimsIdentity?.TryRemoveAndAddClaim(AuthConstants.DEFAULT_OKTA_GROUPS_CLAIM_TYPE, AuthConstants.DebugOktaGroupQueryMap[_profileProvider.ConfigurationOverrides.OktaGroup]);
            //}
            //else if (!_webHostEnvironment.IsProduction())
            //{
            //    claimsIdentity?.TryRemoveAndAddClaim(AuthConstants.DEFAULT_OKTA_GROUPS_CLAIM_TYPE, CrmAdminOktaGroups.SiteAdmin);
            //}
            return claimsPrincipal; ;
        }

        
    }
}
