using System.ComponentModel.DataAnnotations;

namespace BaseLibrary.DTOs
{
    public class Register : AccountBase
    {
        [Required]
        [MinLength(5)]
        [MaxLength(50)]
        public string? FullName { get; set; }
        [DataType(DataType.Password)]
        [Compare(nameof(Password))] 
        [Required]
        public string? ConfirmPassword { get; set; }

    }
}
