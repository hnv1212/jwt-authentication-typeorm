import { UserDTO } from "../dto/response/user.dto";
import { User } from "../entity/User";

export class EntityToDTO {
    public static userToDTO(user: User): UserDTO {
        const userDTO: UserDTO = new UserDTO();
        userDTO.id = user.id;
        userDTO.username = user.username;
        userDTO.email = user.email;
        userDTO.age = user.age;

        return userDTO;
    }
}