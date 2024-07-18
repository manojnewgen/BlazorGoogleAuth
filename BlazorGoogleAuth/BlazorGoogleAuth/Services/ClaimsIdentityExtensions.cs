using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;

namespace BlazorGoogleAuth.Services
{
    public static class ClaimsIdentityExtensions
    {
        public static List<string> Roles(this ClaimsIdentity identity)
        {
            return identity.Claims
                           .Where(c => c.Type == ClaimTypes.Role)
                           .Select(c => c.Value)
                           .ToList();
        }

        public static List<string> Groups(this ClaimsIdentity identity)
        {
            return identity.Claims
                           .Where(c => c.Type == "group")
                           .Select(c => c.Value)
                           .ToList();
        }

        public static void TryRemoveAndAddClaim(this ClaimsIdentity identity, string type, string value)
        {
            var success = true;
            while (success)
                success = identity.TryRemoveClaim(identity.Claims.Where(c => c.Type.Equals(type)).FirstOrDefault());

            identity?.AddClaim(new Claim(type, value));
        }
    }
}
