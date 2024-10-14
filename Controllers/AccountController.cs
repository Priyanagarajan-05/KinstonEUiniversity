/*
using Microsoft.AspNetCore.Mvc;
using EUnivKinston.Models;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Linq;

namespace EUnivKinston.Controllers
{
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;

        public AccountController(AppDbContext context)
        {
            _context = context;
        }

        // GET: Login
        public IActionResult Login()
        {
            return View();
        }

        // POST: Login
        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            // Find user in the database based on email and password
            var user = _context.Users.FirstOrDefault(u => u.Email == email && u.Password == password);
            if (user != null)
            {
                // Store user details in session
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserRole", user.Role);
                HttpContext.Session.SetString("UserName", user.Name); // Store user name in session

                // Redirect based on user role
                switch (user.Role)
                {
                    case "Admin":
                        return RedirectToAction("AdminDashboard");
                    case "Professor":
                        return RedirectToAction("ProfessorDashboard");
                    case "Student":
                        return RedirectToAction("StudentDashboard");
                }
            }
            // Invalid login
            ModelState.AddModelError("", "Invalid email or password");
            return View();
        }

        // Logout action
        public IActionResult Logout()
        {
            // Clear session and redirect to login page
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // Admin Dashboard
        public IActionResult AdminDashboard()
        {
            if (HttpContext.Session.GetString("UserRole") == "Admin")
            {
                ViewBag.AdminName = HttpContext.Session.GetString("UserName"); // Pass the name to the view
                return View();
            }
            return RedirectToAction("Login");
        }

        // Professor Dashboard
        public IActionResult ProfessorDashboard()
        {
            if (HttpContext.Session.GetString("UserRole") == "Professor")
            {
                ViewBag.ProfessorName = HttpContext.Session.GetString("UserName"); // Pass the professor's name to the view
                return View();
            }
            return RedirectToAction("Login");
        }

        // Student Dashboard
        public IActionResult StudentDashboard()
        {
            if (HttpContext.Session.GetString("UserRole") == "Student")
            {
                ViewBag.StudentName = HttpContext.Session.GetString("UserName"); // Pass the student's name to the view
                return View();
            }
            return RedirectToAction("Login");
        }

        // GET: /Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        // POST: /Account/Register
        [HttpPost]
        public IActionResult Register(User model)
        {
            if (ModelState.IsValid)
            {
                // Logic to save the user to the database
                _context.Users.Add(model);
                _context.SaveChanges();

                return RedirectToAction("Login");
            }

            return View(model);
        }


    }
}*/

using Microsoft.AspNetCore.Mvc;
using EUnivKinston.Models;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Linq;

namespace EUnivKinston.Controllers
{
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;

        public AccountController(AppDbContext context)
        {
            _context = context;
        }

        // GET: Login
        public IActionResult Login()
        {
            return View();
        }

        // POST: Login
        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            // Find user in the database based on email and password
            var user = _context.Users.FirstOrDefault(u => u.Email == email && u.Password == password);
            if (user != null)
            {
                // Store user details in session
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserRole", user.Role);
                HttpContext.Session.SetString("UserName", user.Name); // Store user name in session

                // Redirect based on user role
                switch (user.Role)
                {
                    case "Admin":
                        return RedirectToAction("AdminDashboard");
                    case "Professor":
                        return RedirectToAction("ProfessorDashboard");
                    case "Student":
                        return RedirectToAction("StudentDashboard"); // Redirect to Student Dashboard
                }
            }

            // Invalid login
            ModelState.AddModelError("", "Invalid email or password");
            return View();
        }

        // Logout action
        public IActionResult Logout()
        {
            // Clear session and redirect to login page
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // Admin Dashboard
        public IActionResult AdminDashboard()
        {
            if (HttpContext.Session.GetString("UserRole") == "Admin")
            {
                ViewBag.AdminName = HttpContext.Session.GetString("UserName"); // Pass the name to the view
                return View();
            }
            return RedirectToAction("Login");
        }

        // Professor Dashboard
        public IActionResult ProfessorDashboard()
        {
            if (HttpContext.Session.GetString("UserRole") == "Professor")
            {
                ViewBag.ProfessorName = HttpContext.Session.GetString("UserName"); // Pass the professor's name to the view
                return View();
            }
            return RedirectToAction("Login");
        }

        // Student Dashboard
        public IActionResult StudentDashboard()
        {
            if (HttpContext.Session.GetString("UserRole") == "Student")
            {
                ViewBag.StudentName = HttpContext.Session.GetString("UserName"); // Pass the student's name to the view
                return View();
            }
            return RedirectToAction("Login");
        }

        // GET: /Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        // POST: /Account/Register
        [HttpPost]
        public IActionResult Register(User model)
        {
            if (ModelState.IsValid)
            {
                // Logic to save the user to the database
                _context.Users.Add(model);
                _context.SaveChanges();

                return RedirectToAction("Login");
            }

            return View(model);
        }
    }
}

/*

// Controllers/AccountController.cs
using Microsoft.AspNetCore.Mvc;
using EUnivKinston.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace EUnivKinston.Controllers
{
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;

        public AccountController(AppDbContext context)
        {
            _context = context;
        }

        // GET: Login
        public IActionResult Login()
        {
            return View();
        }

        // POST: Login
        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            // Verify hashed password
            if (user != null && VerifyPassword(password, user.PasswordHash))
            {
                // Store user details in session
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserRole", user.Role);
                HttpContext.Session.SetString("UserName", user.Name);

                switch (user.Role)
                {
                    case "Admin":
                        return RedirectToAction("AdminDashboard");
                    case "Professor":
                        return RedirectToAction("ProfessorDashboard");
                    case "Student":
                        return RedirectToAction("StudentDashboard");
                }
            }

            ModelState.AddModelError("", "Invalid email or password");
            return View();
        }

        // Logout action
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // GET: /Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        // POST: /Account/Register
        [HttpPost]
        public async Task<IActionResult> Register(User model)
        {
            if (ModelState.IsValid)
            {
                // Hash the password before storing
                model.PasswordHash = HashPassword(model.Password);
                model.Password = null; // Clear plain password if it's in the model (optional, as it should not be in the model)

                _context.Users.Add(model);
                await _context.SaveChangesAsync();

                return RedirectToAction("Login");
            }

            return View(model);
        }

        // Helper methods for hashing
        private string HashPassword(string password)
        {
            // Generate a salt
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Hash the password with the salt
            var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32));

            return Convert.ToBase64String(salt) + "." + hashed; // Store both salt and hashed password
        }

        private bool VerifyPassword(string password, string hashedPassword)
        {
            var parts = hashedPassword.Split('.');
            var salt = Convert.FromBase64String(parts[0]);
            var hash = parts[1];

            // Hash the provided password with the stored salt
            var hashedInputPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32));

            return hashedInputPassword == hash; // Compare the hashes
        }
    }
}
*/
