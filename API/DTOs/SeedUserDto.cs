namespace API.DTOs;

public class SeedUserDto
{
    public required string Id { get; set; }
    public required string Email { get; set; }
    public DateOnly CareerStartDate { get; set; }
    public string? ImageUrl { get; set; }
    public required string DisplayName { get; set; }
    public DateTime Created { get; set; }
    public DateTime LastActive { get; set; } 
    public required string Role { get; set; }
    public string? Bio { get; set; }
    public required string City { get; set; }
    public required string Country { get; set; }
}