using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Ozz.Core.Authorization
{
    public class TokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(string userId, string userEmail)
        {

            //"JwtSettings": {
            //"SecretKey": "LmN1kTe2vD8RV+h0tM5aKg0mRj+zLkQNL2LwDzY9M9g=", //Minimum 16 karakterli olmalı
            //"Issuer": "https://localhost:7132", //Token'i oluştuan sunucu,Token'i kimin  oluşturudğunu belirler
            //"Audience", //Token'ı kullanacak uygulama,site//Kullanan
            //"ExpiryMinutes": 60
            //}

            //Header
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"];
            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];
            var expireMinutes = int.Parse(jwtSettings["ExpiryMinutes"]);

            //Payload->Claim

            var claims = new[]
            {
                 new Claim(JwtRegisteredClaimNames.Sub,userId), //Token'ın hangi kullanıcıcya ait olduğunu  belirtmek için kullanılır
                 new Claim(JwtRegisteredClaimNames.Email,userEmail), //Token'ın hangi epostaya ait olduğunu  belirtmek için kullanılır
                 new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()) //Token'ı benzersiz yapan mekaznizma ,Her token için farklı bir Jti değeri oluşturur 
            };



            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));//İmza için kullanılacak key'i byte'a dönüştürüyrouz 
            var signinCreds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);//ilgili key ve algoritmaya göre token oluşturulacaktır 

            //Signature 
            var token = new JwtSecurityToken(
               issuer: issuer,
               audience: audience,
               claims: claims,
               expires: DateTime.Now.AddMinutes(expireMinutes),
               signingCredentials: signinCreds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateToken(string userId, string userEmail, List<string> roles)
        {

            //"JwtSettings": {
            //"SecretKey": "LmN1kTe2vD8RV+h0tM5aKg0mRj+zLkQNL2LwDzY9M9g=", //Minimum 16 karakterli olmalı
            //"Issuer": "https://localhost:7132", //Token'i oluştuan sunucu,Token'i kimin  oluşturudğunu belirler
            //"Audience", //Token'ı kullanacak uygulama,site//Kullanan
            //"ExpiryMinutes": 60
            //}

            //Header
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"];
            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];
            var expireMinutes = int.Parse(jwtSettings["ExpiryMinutes"]);

            //Payload->Claim

            var claims = new List<Claim>
            {
                 new Claim(JwtRegisteredClaimNames.Sub,userId), //Token'ın hangi kullanıcıcya ait olduğunu  belirtmek için kullanılır
                 new Claim(JwtRegisteredClaimNames.Email,userEmail), //Token'ın hangi epostaya ait olduğunu  belirtmek için kullanılır
                 new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()) //Token'ı benzersiz yapan mekaznizma ,Her token için farklı bir Jti değeri oluşturur 
            };

            //Kullanıcı rollerini token'a bağla 
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));//İmza için kullanılacak key'i byte'a dönüştürüyrouz 
            var signinCreds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);//ilgili key ve algoritmaya göre token oluşturulacaktır 

            //Signature 
            var token = new JwtSecurityToken(
               issuer: issuer,
               audience: audience,
               claims: claims,
               expires: DateTime.Now.AddMinutes(expireMinutes),
               signingCredentials: signinCreds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

/*
 JWT Nedir ? 
1)Header(Başlık)
 a)Tokenin Türü (JWT)
 b)İmzalama algoritması örneğin HMAC SHA256
2)Payload(Veri)
  Token içerisinde taşınan veri,Uygulama içeiridne ihtiayaç olunan  veriler Json object olarak tutulur 

3)Signature(İmza) 
 Header ve Payload bilgilerini sırayla bir araya getirip ,birleştirir ve Bir imza oluşturur.
Token'un güvenliğini sağlamak ve değiştirilmeden kullanılmasını sağlar 

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Header.Payload.Signature

 */