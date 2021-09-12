import "reflect-metadata";
import { createConnection } from "typeorm";
import { User } from "./entity/User";
import * as express from 'express';
import { RegisterDTO } from "./dto/request/register.dto";
import { Database } from "./database";
import { PasswordHash } from "./security/passwordhash";
import { AuthenticationDTO } from "./dto/response/authentication.dto";
import { UserDTO } from "./dto/response/user.dto";
import { JWT } from "./security/jwt";
import { LoginDTO } from "./dto/request/login.dto";
import { EntityToDTO } from "./util/entityToDTO";
import { RefreshTokenDTO } from "./dto/request/refreshToken.dto";

const app = express();
app.use(express.json());

Database.initialize();

app.post('/register', async (req: express.Request, res: express.Response) => {
    try {
        const body: RegisterDTO = req.body;

        // validate the body
        if (body.password !== body.repeatPassword) {
            throw new Error("Repeat password does not match the password");
        }
        // validate ig the email is already being used
        if (await Database.userRepository.findOne({ email: body.email })) {
            throw new Error("Email is already being used.");
        }
        // store the user
        const user = new User();
        user.username = body.username;
        user.email = body.email;
        user.password = await PasswordHash.hashPassword(body.password);
        user.age = body.age;

        await Database.userRepository.save(user);

        const authenticationDTO: AuthenticationDTO = new AuthenticationDTO();
        const userDTO: UserDTO = EntityToDTO.userToDTO(user);

        // implement token generation and refresh token
        const tokenAndRefreshToken = await JWT.generateTokenAndRefreshToken(user);
        authenticationDTO.user = userDTO;
        authenticationDTO.token = tokenAndRefreshToken.token;
        authenticationDTO.refreshToken = tokenAndRefreshToken.refreshToken;

        res.json(authenticationDTO);

    } catch (error) {
        res.json({ error });
    }


})

app.post('/login', async (req: express.Request, res: express.Response) => {
    try {
        const body: LoginDTO = req.body;
        // check if the email/user exists
        const user = await Database.userRepository.findOne({ email: body.email })
        if (!user) {
            throw new Error("Email does not exist")
        }
        // check if password is valid
        if (!await PasswordHash.isPasswordValid(body.password, user.password)) {
            throw new Error("Password is invalid")
        }

        // retrieve tokens
        const { token, refreshToken } = await JWT.generateTokenAndRefreshToken(user);

        // generate an authenticationDTO/response
        const authenticationDTO = new AuthenticationDTO();
        authenticationDTO.user = EntityToDTO.userToDTO(user);
        authenticationDTO.token = token;
        authenticationDTO.refreshToken = refreshToken;

        res.json(authenticationDTO);

    } catch (error) {
        res.json({ error });
    }

})

app.post('/refresh/token', async (req: express.Request, res: express.Response) => {
    try {
        const body: RefreshTokenDTO = req.body;
        // check if the jwt token is valid & not expired
        if (!JWT.isTokenValid(body.token)) throw new Error("JWT is not valid");

        const jwtId = JWT.getJwtId(body.token);
        const user = await Database.userRepository.findOne(JWT.getJwtPayloadValueByKey(body.token, "id"));
        if (!user) throw new Error("User does not exist");

        // fetch refresh token from db
        const refreshToken = await Database.refreshTokenRepository.findOne(body.refreshToken);

        // check if the refresh token exists and linked to that jwt token
        if (!await JWT.isRefreshTokenLinkedToToken(refreshToken, jwtId)) {
            throw new Error("Token does not match with Refresh Token")
        }

        // check if the refresh token has expired
        if (await JWT.isRefreshTokenExpired(refreshToken)) {
            throw new Error("Refresh Token has expired");
        }

        // check if the refresh token was used or invalidated
        if (await JWT.isRefreshTokenUsedOrInvalidated(refreshToken)) {
            throw new Error("Refresh Token has been used of invalidated.")
        }

        refreshToken.used = true;
        await Database.refreshTokenRepository.save(refreshToken);

        // generate a fresh pair of token and refreshtoken
        const tokenResults = await JWT.generateTokenAndRefreshToken(user);

        // generate an authentication response
        const authenticationDTO: AuthenticationDTO = new AuthenticationDTO();
        authenticationDTO.user = EntityToDTO.userToDTO(user);
        authenticationDTO.token = tokenResults.token;
        authenticationDTO.refreshToken = tokenResults.refreshToken;
        res.json(authenticationDTO);
    } catch (error) {
        res.json({ error });
    }


})

app.listen(4000, () => console.log('Server'));

createConnection().then(async connection => {

    // console.log("Inserting a new user into the database...");
    // const user = new User();
    // user.firstName = "Timber";
    // user.lastName = "Saw";
    // user.age = 25;
    // await connection.manager.save(user);
    // console.log("Saved a new user with id: " + user.id);

    // console.log("Loading users from the database...");
    // const users = await connection.manager.find(User);
    // console.log("Loaded users: ", users);

    // console.log("Here you can setup and run express/koa/any other framework.");



}).catch(error => console.log(error));
