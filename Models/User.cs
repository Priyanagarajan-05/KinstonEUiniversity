// Models/ApplicationUser.cs


using System.ComponentModel.DataAnnotations;
namespace EUnivKinston.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; } // Admin, Student, or Professor
    }
}

/*
using System.ComponentModel.DataAnnotations;
namespace EUnivKinston.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; } // Store hashed password
        public string Role { get; set; }
    }

}*/