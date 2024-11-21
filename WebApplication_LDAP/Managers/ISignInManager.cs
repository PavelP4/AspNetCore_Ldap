namespace WebApplication_LDAP.Managers
{
    public interface ISignInManager
    {
        Task<bool> SignIn(string username, string password);
        Task SignOut();
    }
}
