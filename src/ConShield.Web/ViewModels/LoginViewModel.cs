using System.ComponentModel.DataAnnotations;

namespace ConShield.Web.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Введите логин")]
    [Display(Name = "Логин")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Введите пароль")]
    [Display(Name = "Пароль")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Запомнить меня")]
    public bool RememberMe { get; set; }
}
