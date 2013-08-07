using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace RelyingParty1.Controllers
{
    public class UserController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Logout()
        {
            // Load Identity Configuration
            FederationConfiguration config = FederatedAuthentication.FederationConfiguration;

            // Sign out of WIF.
            WSFederationAuthenticationModule.FederatedSignOut(new Uri(ConfigurationManager.AppSettings["ida:Issuer"]), new Uri(config.WsFederationConfiguration.Realm));

            return View();
        }
    }
}
