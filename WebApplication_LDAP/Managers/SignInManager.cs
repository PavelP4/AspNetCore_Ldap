using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.DirectoryServices.Protocols;
using System.Security.Claims;
using System.Text;
using WebApplication_LDAP.Models;

namespace WebApplication_LDAP.Managers
{
    public class SignInManager : ISignInManager
    {
        private readonly ConfigurationAD _configurationAD;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public SignInManager(
            IOptions<ConfigurationAD> configurationAD,
            IHttpContextAccessor httpContextAccessor
            )
        {
            _configurationAD = configurationAD.Value;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<bool> SignIn(string username, string password)
        {
            var adUser = new ADUser();

            var searchResults = ADHelper.SearchInAD(
                _configurationAD.LDAPserver,
                _configurationAD.Port,
                _configurationAD.Domain,
                username,
                password,
                $"CN=Users,{_configurationAD.LDAPQueryBase}",
                //new StringBuilder("(&")
                //    .Append("(objectCategory=person)")
                //    .Append("(objectClass=user)")
                //    .Append($"(memberOf={_configurationAD.DomainAdmins})")
                //    .Append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
                //    .Append($"(sAMAccountName={username})")
                //    .Append(")")
                new StringBuilder("(objectClass=*)")
                    .ToString(),
                SearchScope.Subtree,
                [
                "objectGUID",
                "sAMAccountName",
                "displayName",
                "mail",
                "whenCreated",
                "memberOf"
                ]
            );

            var results = searchResults.Entries.Cast<SearchResultEntry>();
            if (results.Any())
            {
                var resultsEntry = results.First();
                adUser = new ADUser()
                {
                    ObjectGUID = new Guid((resultsEntry.Attributes["objectGUID"][0] as byte[])!),
                    SAMAccountName = resultsEntry.Attributes["sAMAccountName"][0].ToString()!,
                    DisplayName = resultsEntry.Attributes["displayName"][0].ToString()!,
                    Mail = resultsEntry.Attributes["mail"][0].ToString()!,
                    WhenCreated = DateTime.ParseExact(
                        resultsEntry.Attributes["whenCreated"][0].ToString()!,
                        "yyyyMMddHHmmss.0Z",
                        System.Globalization.CultureInfo.InvariantCulture
                    )
                };
                var groups = resultsEntry.Attributes["memberOf"];
                foreach (var g in groups)
                {
                    var groupNameBytes = g as byte[];
                    if (groupNameBytes != null)
                    {
                        adUser.MemberOf.Add(Encoding.Default.GetString(groupNameBytes).ToLower());
                    }
                }
            }
            else
            {
                Console.WriteLine(
                    $"There is no such user in the [crew] group: {username}"
                );
                return false;
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, adUser.ObjectGUID.ToString()),
                new Claim(ClaimTypes.WindowsAccountName, adUser.SAMAccountName),
                new Claim(ClaimTypes.Name, adUser.DisplayName),
                new Claim(ClaimTypes.Email, adUser.Mail),
                new Claim("whenCreated", adUser.WhenCreated.ToString("yyyy-MM-dd"))
            };
            // perhaps it should add a role for every group, but we only need one for now
            //if (adUser.MemberOf.Contains(_configurationAD.Managers.ToLower()))
            //{
            //    claims.Add(new Claim(ClaimTypes.Role, "managers"));
            //}

            var identity = new ClaimsIdentity(
                claims,
                "LDAP", // what goes to User.Identity.AuthenticationType
                ClaimTypes.Name, // which claim is for storing user name in User.Identity.Name
                ClaimTypes.Role // which claim is for storing user roles, needed for User.IsInRole()
            );
            var principal = new ClaimsPrincipal(identity);

            if (_httpContextAccessor.HttpContext != null)
            {
                try
                {
                    await _httpContextAccessor.HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        principal
                    );
                    return true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Signing in has failed. {ex.Message}");
                }
            }

            return false;
        }

        public async Task SignOut()
        {
            if (_httpContextAccessor.HttpContext != null)
            {
                await _httpContextAccessor.HttpContext.SignOutAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme
                );
            }
            else
            {
                throw new Exception(
                    "For some reasons, HTTP context is null, signing out cannot be performed"
                );
            }
        }
    }
}
