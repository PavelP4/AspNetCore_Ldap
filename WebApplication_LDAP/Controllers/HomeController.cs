using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.DirectoryServices.Protocols;
using System.Text;

namespace WebApplication_LDAP.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        private readonly ConfigurationAD _configurationAD;

        public HomeController(
            IOptions<ConfigurationAD> configurationAD
            )
        {
            _configurationAD = configurationAD.Value;
        }

        [AllowAnonymous]
        [HttpPost("Connect")]
        public string Get()
        {
            var attributesToQuery = new string[]
            {
                "objectGUID",
                "sAMAccountName",
                "displayName",
                "mail",
                "whenCreated"
            };
            var searchResults = ADHelper.SearchInAD(
                _configurationAD.LDAPserver,
                _configurationAD.Port,
                _configurationAD.UserDomain,
                _configurationAD.Username,
                _configurationAD.Password,
                $"CN=Users,{_configurationAD.LDAPQueryBase}",
                //new StringBuilder("(&")
                //    .Append("(objectCategory=person)")
                //    .Append("(objectClass=user)")
                //    .Append($"(memberOf={_configurationAD.DomainAdmins})")
                //    .Append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
                //    .Append(")")
                new StringBuilder("(objectClass=*)")
                    .ToString(),
                SearchScope.Subtree,
                attributesToQuery
            );


            return "OK";
        }

        [HttpGet]
        public string Index()
        {
            return "OK";
        }
    }
}
