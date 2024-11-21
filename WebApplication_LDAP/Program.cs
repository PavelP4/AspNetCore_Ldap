
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using System.Text;
using WebApplication_LDAP.Managers;

namespace WebApplication_LDAP
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var configuration = builder.Configuration;
            // Add services to the container.
            builder.Services.Configure<ConfigurationAD>(c =>
            {
                c.Port = configuration.GetSection("AD:port").Get<int>();

                c.Zone = configuration.GetSection("AD:zone").Value!;
                c.Domain = configuration.GetSection("AD:domain").Value!;
                c.Subdomain = configuration.GetSection("AD:subdomain").Value!;

                c.UserDomain = configuration.GetSection("AD:userdomain").Value!;
                c.Username = configuration.GetSection("AD:username").Value!;
                c.Password = configuration.GetSection("AD:password").Value!;

                // connection string with port doesn't work on GNU/Linux and Mac OS
                //c.LDAPserver = $"{c.Subdomain}.{c.Domain}.{c.Zone}:{c.Port}";
                c.LDAPserver = $"{c.Domain}.{c.Zone}";
                        // that depends on how it is in your LDAP server
                        //c.LDAPQueryBase = $"DC={c.Subdomain},DC={c.Domain},DC={c.Zone}";
                c.LDAPQueryBase = $"DC={c.Domain},DC={c.Zone}";

                c.DomainAdmins = new StringBuilder()
                    .Append($"CN={configuration.GetSection("AD:domainAdmins").Value},")
                    // check which CN (Users or Groups) your LDAP server has the groups in
                    .Append($"CN=Users,{c.LDAPQueryBase}")
                    .ToString();
             });

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddScoped<ISignInManager, SignInManager>();

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(
                    options =>
                    {
                        options.ExpireTimeSpan = TimeSpan.FromDays(11);

                        options.LoginPath = "/account/login";
                        options.AccessDeniedPath = "/account/access-denied";
                    }
                );

            builder.Services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });

            builder.Services.AddControllersWithViews(
                options =>
                {
                    options.Filters.Add(new AuthorizeFilter());
                }
            );

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
