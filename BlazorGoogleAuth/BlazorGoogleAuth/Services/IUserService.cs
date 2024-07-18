using BlazorServerApp.Data;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BlazorServerApp.Services
{
    public interface IUserService
    {
        public Task<string> LoginAsync(User user);
        public Task<bool> AuthenticateWithEntrust(string username, string password);
        public Task<User> RegisterUserAsync(User user);
      //  public Task<User> GetUserByAccessTokenAsync(string accessToken);
       // public Task<User> RefreshTokenAsync(RefreshRequest refreshRequest);
    }
}
