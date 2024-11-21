namespace WebApplication_LDAP
{
    public class ConfigurationAD
    {
        public int Port { get; set; } = 389;
        public string Zone { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string Subdomain { get; set; } = string.Empty;

        public string UserDomain {  get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        public string LDAPserver { get; set; } = string.Empty;
        public string LDAPQueryBase { get; set; } = string.Empty;

        public string DomainAdmins { get; set; } = string.Empty;
    }
}
