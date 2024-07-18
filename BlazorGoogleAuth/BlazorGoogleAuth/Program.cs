using BlazorGoogleAuth.Authorization;
using BlazorGoogleAuth.Client.Pages;
using BlazorGoogleAuth.Components;
using BlazorGoogleAuth.Components.Account;
using BlazorGoogleAuth.Data;
using BlazorGoogleAuth.Services;
using BlazorServerApp.Data;
using BlazorServerApp.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

//var appSettingSection = builder.Configuration.GetSection("/*AppSettings*/");
//builder.Services.Configure<AppSettings>(appSettingSection);

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set the session timeout as needed
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true; // Make the session cookie essential
});

builder.Services.AddSingleton<HybridAuthState>();
builder.Services.AddScoped<AuthenticationStateProvider>(provider => provider.GetRequiredService<HybridAuthService>());
//builder.Services.AddScoped<AuthenticationStateProvider, HybridAuthState>();

builder.Services.AddSingleton<HybridAuthService>();
builder.Services.AddHttpContextAccessor();
builder.Configuration.AddUserSecrets<Program>();

builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("ApiSettings"));
builder.Services.AddHttpClient<IUserService, UserService>();
builder.Services.AddScoped<EntrustAuthService>();



builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
//builder.Services.AddScoped<AuthenticationStateProvider, PersistingRevalidatingAuthenticationStateProvider<ApplicationUser>>();

/*builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddIdentityCookies();

builder.Services.AddAuthentication().AddGoogle(googleOptions =>
{
    googleOptions.ClientId = builder.Configuration["Authentication:Google:ClientId"];
    googleOptions.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
});

builder.Services.AddAuthentication().AddMicrosoftAccount(microsoftOptions =>
{
    microsoftOptions.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
    microsoftOptions.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
    microsoftOptions.AuthorizationEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
    microsoftOptions.TokenEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
}); */

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddGoogle(googleOptions =>
{
    googleOptions.ClientId = builder.Configuration["Authentication:Google:ClientId"];
    googleOptions.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
})
.AddMicrosoftAccount(microsoftOptions =>
{
    microsoftOptions.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
    microsoftOptions.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
    microsoftOptions.AuthorizationEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
    microsoftOptions.TokenEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
}).AddIdentityCookies();

builder.Services.AddAuthorizationCore();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentityCore<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

builder.Services.AddServerSideBlazor(options =>
{
    options.DetailedErrors = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
    app.UseMigrationsEndPoint();

}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(BlazorGoogleAuth.Client._Imports).Assembly);

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.Run();
