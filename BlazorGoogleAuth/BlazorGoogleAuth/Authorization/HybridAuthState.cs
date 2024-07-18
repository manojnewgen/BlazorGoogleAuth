using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlazorGoogleAuth.Authorization
{
    public class HybridAuthState : AuthenticationStateProvider
    {
        public bool IsAuthenticated { get; private set; }
        public string[] Roles { get; private set; }
        public string ClaimName { get; private set; }= "Hybrid User";
       

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var identity = IsAuthenticated ? new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "Hybrid User") }, "Hybrid authentication") : new ClaimsIdentity();

            if (IsAuthenticated && Roles != null && Roles.Length > 0)
            {
                foreach (var role in Roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
            }

            var user = new ClaimsPrincipal(identity);

            return Task.FromResult(new AuthenticationState(user));
        }

        public void SetAuthenticationState(bool isAuthenticated, string[] roles = null)
        {
            IsAuthenticated = isAuthenticated;
            Roles = roles;
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }
}