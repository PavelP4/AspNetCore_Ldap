using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApplication_LDAP.Managers;

namespace WebApplication_LDAP.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ISignInManager _signInManager;

        public AccountController(ISignInManager signInManager)
        {
            _signInManager = signInManager;
        }

        [AllowAnonymous]
        [HttpGet("Login")]
        public async Task<bool> LogIn(string userName, string password)
        { 
            var result = await _signInManager.SignIn(userName, password);

            return result;
        }


        [HttpPost("Logout")]
        public async Task<bool> LogOut()
        { 
            await _signInManager.SignOut();

            return true;
        }
    }
}
