using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Configuration;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;

namespace RelyingParty1
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);

            // Only switch to RSA encryption for SSO if a certificateReference exists in the federationConfiguration web.config section. Otherwise, default to DPAPI. <certificateReference x509FindType="FindByThumbprint" findValue="DF4CE1055D36337F017E1A1F9376B560FC40DA77"/>
            foreach (FederationConfigurationElement config in SystemIdentityModelServicesSection.Current.FederationConfigurationElements)
            {
                CertificateReferenceElement certificate = config.ServiceCertificate.CertificateReference;
                if (!string.IsNullOrEmpty(certificate.FindValue))
                {
                    // Initialize single-sign-on certificate reference.
                    FederatedAuthentication.FederationConfigurationCreated += OnServiceConfigurationCreated;
                }
            }
        }

        void OnServiceConfigurationCreated(object sender, FederationConfigurationCreatedEventArgs e)
        {
            // Change cookie encryption type from DPAPI to RSA. This avoids a security exception due to a cookie size limit with the SSO cookie. See http://fabriccontroller.net/blog/posts/key-not-valid-for-use-in-specified-state-exception-when-working-with-the-access-control-service/
            var sessionTransforms = new List<CookieTransform>(new CookieTransform[] {
                new DeflateCookieTransform(),
                new RsaEncryptionCookieTransform(e.FederationConfiguration.ServiceCertificate),
                new RsaSignatureCookieTransform(e.FederationConfiguration.ServiceCertificate)
            });

            var sessionHandler = new SessionSecurityTokenHandler(sessionTransforms.AsReadOnly());
            e.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.AddOrReplace(sessionHandler);
        }
    }
}