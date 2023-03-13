using Microsoft.Extensions.Options;
using MyApp.Models.Entities;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Identity;
using MyApp.Models.Identity;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
var connectionString = builder.Configuration.GetConnectionString("MsSQLConnection");
builder.Services.AddDbContext<MyCvContext>(options =>{
    options.UseSqlServer(connectionString);});
builder.Services.AddDbContext<ApplicationContext>(options => options.UseSqlServer("MsSQLAConnection"));
builder.Services.AddIdentity<Users,IdentityRole>().AddEntityFrameworkStores<ApplicationContext>().AddDefaultTokenProviders();
builder.Services.Configure<IdentityOptions>(options=> {
    // Passwords
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    // LockOut
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromHours(1);
    options.Lockout.AllowedForNewUsers = true;
    

    // options.User.AllowedUserNameCharacters = "";
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = false;
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedPhoneNumber = false;

});
builder.Services.ConfigureApplicationCookie(options =>{
    options.LoginPath = "/admin/login";
    options.LogoutPath="/admin/logout";
    options.AccessDeniedPath = "/admin/login";
    
    options.SlidingExpiration = true; // 20 minutes off
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.Cookie = new CookieBuilder
    {
        HttpOnly = true,
        Name = ".meliksah-simsek.Security.Cookie"
    };
});
builder.Services.AddSession();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}


app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSession();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "custom1",
    pattern: "{controller=Home}/{action=Index}/{id1?}/{id2?}");

app.MapControllerRoute(
    name: "custom2",
    pattern: "{controller=Home}/{action=Index}/{id1?}/{id2?}/{id3?}");
app.Run();
