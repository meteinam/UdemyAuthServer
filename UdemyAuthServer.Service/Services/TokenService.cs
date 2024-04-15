using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SharedLibrary.Configuration;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UdemyAuthServer.Core.Configuration;
using UdemyAuthServer.Core.DTOs;
using UdemyAuthServer.Core.Models;
using UdemyAuthServer.Core.Services;

namespace UdemyAuthServer.Service.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<UserApp> _userManager;
        private readonly CustomTokenOptions _customTokenOptions;

        public TokenService(UserManager<UserApp> userManager, IOptions<CustomTokenOptions> options)
        {
            _userManager = userManager;
            _customTokenOptions = options.Value;
        }
        private string CreateRefreshToken() 
        {
            var numberByte = new Byte[32];
            using var rnd=RandomNumberGenerator.Create();
            rnd.GetBytes(numberByte);
            return Convert.ToBase64String(numberByte);
        }
        private IEnumerable<Claim> GetClaims(UserApp userApp, List<string> audiences) 
        {
            var userList = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userApp.Id),
                new Claim(JwtRegisteredClaimNames.Email, userApp.Email),
                new Claim(ClaimTypes.Name, userApp.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

            };
            userList.AddRange(audiences.Select(x => new Claim(JwtRegisteredClaimNames.Aud, x)));
            return userList;
        }
        private IEnumerable<Claim> GetClaimsByClient(Client client) 
        {
            var claims = new List<Claim>();
            claims.AddRange(client.Audiences.Select(x => new Claim(JwtRegisteredClaimNames.Aud, x)));

            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString());
            new Claim(JwtRegisteredClaimNames.Sub, client.Id);

            return claims;

        }
        public TokenDto CreateToken(UserApp userApp)
        {
            var acccessTokenExpiration = DateTime.Now.AddMinutes(30);
            var refreshTokenExpiration = DateTime.Now.AddMinutes(30);
            var securityKey=SignService.GetSymmetricSecurityKey(_customTokenOptions.SecurityKey);
            SigningCredentials signingCredentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256Signature);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
                issuer: _customTokenOptions.Issuer,
                expires: acccessTokenExpiration,
                notBefore: DateTime.Now,
                claims: GetClaims(userApp, _customTokenOptions.Audience),
                signingCredentials: signingCredentials
                );
            var handler = new JwtSecurityTokenHandler();
            var token=handler.WriteToken(jwtSecurityToken);
            var tokenDto = new TokenDto
            {
                AccesToken = token,
                RefreshToken = CreateRefreshToken(),
                AccesTokenExpiration = acccessTokenExpiration,
                RefreshTokenExpiration = refreshTokenExpiration,
            };
            return tokenDto;
        }

        public ClientTokenDto CreateTokenByClient(Client client)
        {
            var acccessTokenExpiration = DateTime.Now.AddMinutes(_customTokenOptions.AccessTokenExpiration);
            var securityKey = SignService.GetSymmetricSecurityKey(_customTokenOptions.SecurityKey);
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
                issuer: _customTokenOptions.Issuer,
                expires: acccessTokenExpiration,
                notBefore: DateTime.Now,
                claims: GetClaimsByClient(client),
                signingCredentials: signingCredentials
                );
            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(jwtSecurityToken);
            var tokenDto = new ClientTokenDto
            {
                AccesToken = token,
                AccesTokenExpiration = acccessTokenExpiration,
            };
            return tokenDto;
        }
    }
}
