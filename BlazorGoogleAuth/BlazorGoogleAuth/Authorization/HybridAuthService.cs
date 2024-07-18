using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlazorGoogleAuth.Authorization
{
    public class HybridAuthService : AuthenticationStateProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public bool IsAuthenticated { get; private set; }
        public string[] Roles { get; private set; }
        public string ClaimName { get; set; } = "Hybrid User";

        public HybridAuthService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var identity = IsAuthenticated ? new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, ClaimName) }, "Hybrid authentication") : new ClaimsIdentity();

            if (IsAuthenticated && Roles != null && Roles.Length > 0)
            {
                foreach (var role in Roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
            }

            var user = new ClaimsPrincipal(identity);
            var httpContext = _httpContextAccessor.HttpContext;
            httpContext.User = user;

            return Task.FromResult(new AuthenticationState(user));
        }

        public async void SetAuthenticationState(bool isAuthenticated, string[] roles = null)
        {
            IsAuthenticated = isAuthenticated;
            Roles = roles ?? new string[] { };
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
         
        }

        public void SetAccessToken(string accessToken)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.Session != null)
            {
                if (accessToken != null)
                {
                    httpContext.Session.SetString("AccessToken", accessToken);
                }
                else
                {
                    // Handle null accessToken case if needed
                    throw new ArgumentNullException(nameof(accessToken), "Access token cannot be null.");
                }
            }
            else
            {
                throw new InvalidOperationException("Session has not been configured for this application or request.");
            }
        }


    }
}
