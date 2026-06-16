using System.ComponentModel.DataAnnotations;

namespace ConShield.Web.ViewModels;

public class UserExceptionEditViewModel
{
    public int Id { get; set; }

    [Required(ErrorMessage = "Укажите логин пользователя")]
    [Display(Name = "Логин пользователя")]
    public string UserLogin { get; set; } = string.Empty;

    [Required(ErrorMessage = "Укажите исходную систему")]
    [Display(Name = "Исходная система")]
    public string SourceSystem { get; set; } = string.Empty;

    [Required(ErrorMessage = "Укажите тип исключения")]
    [Display(Name = "Тип исключения")]
    public string ExceptionType { get; set; } = string.Empty;

    [Required(ErrorMessage = "Введите описание")]
    [Display(Name = "Описание")]
    public string Description { get; set; } = string.Empty;

    [Display(Name = "Активно")]
    public bool IsActive { get; set; } = true;

    [Display(Name = "Дата окончания")]
    [DataType(DataType.DateTime)]
    public DateTime? ExpiresAtUtc { get; set; }

    [Display(Name = "Дата окончания (GMT+3)")]
    [DataType(DataType.DateTime)]
    public DateTime? ExpiresAtLocal { get; set; }
}
