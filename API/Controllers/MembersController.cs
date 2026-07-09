using API.Data;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [Authorize]
    public class MembersController(IMemberRepository memberRepository) : BaseApiController
    {
        [HttpGet] //localhost:5000/api/members/
        public async Task<ActionResult<IReadOnlyList<Member>>> GetMembers()
        {
            return Ok(memberRepository.GetMembersAsync());
        }


        [HttpGet("{id}")] //localhost:5000/api/members/nid-id
        public async Task<ActionResult<Member>> GetMember(string id)
        {
            var member = await memberRepository.GetMemberByIdAsync(id);
            if (member == null) return NotFound();
            return member;
        }

        [HttpGet("{id}/photos")]
        public async Task<ActionResult<IReadOnlyList<Photo>>> GetMemberPhotos(string id)
        {
            return Ok(memberRepository.GetPhotosForMemberAsync(id));
        }
    }
}
