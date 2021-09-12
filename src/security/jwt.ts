import * as jwt from 'jsonwebtoken';
import { User } from '../entity/User';
import { v4 as uuidv4 } from 'uuid';
import { RefreshToken } from '../entity/RefreshToken';
import * as moment from 'moment';
import { Database } from '../database';

export class JWT {
    private static JWT_SECRET = "123456";

    public static async generateTokenAndRefreshToken(user: User) {
        // specify a payload thats holds the user id (and) email
        const payload = {
            id: user.id,
            email: user.email
        }

        // specify a secret key for jwt generation
        // specify when does the token expires
        // specify jwtid (an id of that token) (needed for the refresh token, as a refresh token only points to one single unique token)
        const jwtId = uuidv4();
        const token = jwt.sign(payload, this.JWT_SECRET, {
            // expires
            expiresIn: "1h",
            // jwtId
            jwtid: jwtId,
            // the subject should be the users id (primary key)
            subject: user.id.toString()
        })

        // create a refresh token
        const refreshToken = await this.generateRefreshTokenForUserAndToken(user, jwtId);
        // link that token with the refresh token


        return {token, refreshToken};
    }

    private static async generateRefreshTokenForUserAndToken(user: User, jwtId: string) {
        // create a new record of refresh token
        const refreshToken = new RefreshToken();
        refreshToken.user = user;
        refreshToken.jwtId = jwtId;
        refreshToken.expiryDate = moment().add(10, "d").toDate();

        // store this refresh token
        await Database.refreshTokenRepository.save(refreshToken);

        return refreshToken.id;
    }

    public static isTokenValid(token: string) {
        try {
            jwt.verify(token, this.JWT_SECRET, { ignoreExpiration: false })
            return true;
        } catch (error) {
            return false;
        }
        
    }

    public static getJwtId(token: string) {
        const decodedToken = jwt.decode(token);
        return decodedToken['jti'];
    }

    public static async isRefreshTokenLinkedToToken(refreshToken: RefreshToken, jwtId: string) {

        if(!refreshToken) return false;

        if(refreshToken.jwtId !== jwtId) return false;

        return true;
    }

    public static async isRefreshTokenExpired(refreshToken: RefreshToken) {

        if(moment().isAfter(refreshToken.expiryDate)) return true;

        return false;
    }

    public static async isRefreshTokenUsedOrInvalidated(refreshToken: RefreshToken) {
        return refreshToken.used || refreshToken.invalidated;
    }

    public static getJwtPayloadValueByKey(token: string, key: string) {
        const decodedToken = jwt.decode(token);
        return decodedToken[key];
    }
}