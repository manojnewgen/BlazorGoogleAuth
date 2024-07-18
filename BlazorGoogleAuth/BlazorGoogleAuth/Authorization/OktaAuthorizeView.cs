using System.Security.Claims;
using BlazorGoogleAuth.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Rendering;

namespace Crm.Admin.Authorization
{
    /// <summary>
    /// Create custom view which renders the childcontent based on whether user is in the appropriate OKTA group.
    /// Policy and/or roles supplied in the view are matched against the user's group claim or role claim respectively.
    /// </summary>
    public sealed class OktaAuthorizeView : AuthorizeView
    {
        private AuthenticationState? _currentAuthenticationState;
        private bool _isAuthorized;

        //private static Dictionary<string, string[]> _policyMap = new()
        //{
        //    { CrmAdminPolicies.RequireSiteUserRole, new string[] { CrmAdminOktaGroups.SiteUser, CrmAdminOktaGroups.SiteAdmin } },
        //    { CrmAdminPolicies.RequireReleaseManagerRole, new string[] { CrmAdminOktaGroups.ReleaseManager, CrmAdminOktaGroups.SiteAdmin } },
        //    { CrmAdminPolicies.RequireCampaignManagerRole, new string[] { CrmAdminOktaGroups.CampaignManager, CrmAdminOktaGroups.SiteAdmin } },
        //    { CrmAdminPolicies.RequireCampaignManagerOrReleaseManagerRole, new string[] { CrmAdminOktaGroups.CampaignManager, CrmAdminOktaGroups.ReleaseManager, CrmAdminOktaGroups.SiteAdmin } },
        //    { CrmAdminPolicies.RequireSiteAdminRole, new string[] { CrmAdminOktaGroups.SiteAdmin } }
        //};

        [Inject]
        private AuthenticationStateProvider AuthenticationStateProvider { get; init; }

        [Inject]
        private IWebHostEnvironment Environment { get; init; }

        //[Inject]
        //private ProfileProvider ProfileProvider { get; set; }

        [CascadingParameter]
        private Task<AuthenticationState> AuthenticationStateTask { get; set; }

        protected override void BuildRenderTree(RenderTreeBuilder builder)
        {
            if (_currentAuthenticationState is null)
            {
                builder.AddContent(0, Authorizing);
            }
            else if (_isAuthorized)
            {
                var authorizedContent = Authorized ?? ChildContent;
                builder.AddContent(1, authorizedContent?.Invoke(_currentAuthenticationState));
            }
            else
            {
                builder.AddContent(2, NotAuthorized?.Invoke(_currentAuthenticationState));
            }
        }

        protected override async Task OnParametersSetAsync()
        {
            AuthenticationStateTask = AuthenticationStateProvider.GetAuthenticationStateAsync();
            var authenticationState = await AuthenticationStateTask;
            var user = authenticationState.User;
            _currentAuthenticationState = authenticationState;
            _isAuthorized = IsAuthorized(user);
        }

        private bool IsAuthorized(ClaimsPrincipal claimsPrincipal)
        {
            var claimsIdentity = claimsPrincipal.Identities.FirstOrDefault();

            //if (!Environment.IsProduction() && !string.IsNullOrEmpty(ProfileProvider?.ConfigurationOverrides?.OktaGroup) && 
            //    AuthConstants.DebugOktaGroupQueryMap.ContainsKey(ProfileProvider.ConfigurationOverrides.OktaGroup))
            //{
            //    claimsIdentity?.TryRemoveAndAddClaim(AuthConstants.DEFAULT_OKTA_GROUPS_CLAIM_TYPE, AuthConstants.DebugOktaGroupQueryMap[ProfileProvider.ConfigurationOverrides.OktaGroup]);
            //}
            //else if (!Environment.IsProduction())
            //{
            //    return true;
            //}

            //if (!string.IsNullOrEmpty(Policy) && claimsIdentity is not null && !claimsIdentity.Groups().Intersect(_policyMap[Policy], StringComparer.OrdinalIgnoreCase).Any())
            //    return false;

            //if(!string.IsNullOrEmpty(Roles) && claimsIdentity is not null && !IsUserInRequiredRoleList(claimsIdentity, Roles))
            //    return false;
            
            return true;
        }

        private bool IsUserInRequiredRoleList(ClaimsIdentity claimsIdentity, string roles)
        {
            var roleList = roles.Split(',', StringSplitOptions.RemoveEmptyEntries);
            return roleList.Intersect(claimsIdentity.Roles(), StringComparer.OrdinalIgnoreCase).Any();
        }
    }
}
