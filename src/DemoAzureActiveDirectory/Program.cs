using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var azureAdSection = builder.Configuration.GetSection("AzureAd");

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
  .AddMicrosoftIdentityWebApp(configureMicrosoftIdentityOptions: options =>
  {
      //setup the required options tying to your Azure AD
      options.Instance = azureAdSection.GetValue<string>("Instance");
      options.Domain = azureAdSection.GetValue<string>("Domain");
      options.TenantId = azureAdSection.GetValue<string>("TenantId");
      options.ClientId = azureAdSection.GetValue<string>("ClientId");
      options.CallbackPath = azureAdSection.GetValue<string>("CallbackPath");

      //here setup a callback that will be fired when a user is validated, you can use this to find out who logged in and inspect/add claims
      options.Events.OnTokenValidated = ctx =>
      {
          var identity = ctx.Principal?.Identity as ClaimsIdentity;
          if (identity == null)
          {
              throw new ApplicationException("Unsupported identity");
          }

          //get the email address from Claims (Azure AD put this fella in here for us, but it's not always obvious where the email address is, because users could omit certain things)

          //try the email address claim
          var emailAddress = identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

          //if we didn't find that, try the "Mail" claim
          if (emailAddress == null)
          {
              emailAddress = identity.Claims.FirstOrDefault(x => x.Type == "mail")?.Value;
          }

          //if we still don't have it, try their username
          if (emailAddress == null)
          {
              emailAddress = identity.Claims.FirstOrDefault(x => x.Type == "preferred_username")?.Value;
          }

          if (emailAddress == null)
          {
              //are there other claims you might want to try?
              return Task.CompletedTask;
          }

          //by this point you should definitely have an address

          //look up ID in your database using the email address
          Guid customUserId = Guid.NewGuid();

          //add the userid, and any other pertinent info into claims
          identity.AddClaim(new Claim(type: "CustomUserId", customUserId.ToString()));

          return Task.CompletedTask;
      };

  }, openIdConnectScheme: OpenIdConnectDefaults.AuthenticationScheme
            );

builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});


builder.Services.AddRazorPages()
    .AddMvcOptions(options =>
    {
        var policy = new AuthorizationPolicyBuilder()
                         .RequireAuthenticatedUser()
                         .Build();
        options.Filters.Add(new AuthorizeFilter(policy));
    })
    .AddMicrosoftIdentityUI();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
