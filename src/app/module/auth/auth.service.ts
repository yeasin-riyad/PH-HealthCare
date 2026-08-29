/** biome-ignore-all lint/style/useConst: <explanation> */
import bcrypt from "bcryptjs";
import crypto from "crypto";
import ejs from "ejs";
import type { TokenPayload } from "google-auth-library";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import path from "path";
import {
    AuthProvider,
    Role,
    UserStatus,
} from "../../../generated/prisma/enums";
import config from "../../config";
import { googleClient } from "../../lib/googleAuth";
import { transporter } from "../../lib/nodemailer";
import { prisma } from "../../lib/prisma";
import { redisClient } from "../../lib/redis";
import { jwtUtils } from "../../utils/jwt";
import type {
    IForgotPasswordPayload,
    IGoogleLoginPayload,
    ILoginUserPayload,
    IRegisterPatientPayload,
    IRequestUser,
    IResetPasswordPayload,
    IVerifyEmailPayload,
} from "./auth.interface";
import { AppError } from "../../utils/AppError";

const registerPatient = async (payload: IRegisterPatientPayload) => {
    const { name, password, patient: patientData } = payload;

    const email = payload.email.trim().toLowerCase();

    const isUserExists = await prisma.user.findUnique({
        where: { email },
    });

    if (isUserExists) {
        throw new AppError(409, "User with this email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 8);

    const expirationSeconds = 5 * 60;

    const otpKey = `patient-registration-otp:${email}`;
    const otpValue = crypto.randomInt(100000, 1000000).toString();

    await redisClient.set(otpKey, otpValue, {
        expiration: {
            type: "EX",
            value: expirationSeconds,
        },
    });

    const patientRegistrationKey = `patient-registration-data:${email}`;
    const redisUserDataPayload = {
        name,
        email,
        password: hashedPassword,
        patient: patientData,
    };

    await redisClient.set(
        patientRegistrationKey,
        JSON.stringify(redisUserDataPayload),
        {
            expiration: {
                type: "EX",
                value: expirationSeconds,
            },
        },
    );

    const tempatePath = path.join(
        process.cwd(),
        "src/app/templates/registration-user-otp.ejs",
    );

    const templateData = {
        name,
        email,
        otp: otpValue,
        expirationMinutes: expirationSeconds / 60,
    };

    const html = await ejs.renderFile(tempatePath, templateData);

    await transporter.sendMail({
        from: config.email_sender,
        to: email,
        subject: "Email Verification",
        html,
    });
};

const verifyPatientEmail = async (payload: IVerifyEmailPayload) => {
    const otp = payload.otp;
    const email = payload.email.trim().toLowerCase();

    const isUserExist = await prisma.user.findUnique({
        where: { email },
    });

    if (isUserExist?.status === "BLOCKED") {
        throw new AppError(403, "User is Blocked");
    }

    if (isUserExist?.emailVerified) {
        throw new AppError(400, "Email Already Verified");
    }

    if (isUserExist?.isDeleted || isUserExist?.status === "DELETED") {
        throw new AppError(404, "User is Deleted");
    }

    const otpKey = `patient-registration-otp:${email}`;

    const redisOtp = await redisClient.get(otpKey);

    if (!redisOtp) {
        throw new AppError(400, "Invalid OTP");
    }

    if (redisOtp !== otp) {
        throw new AppError(400, "OTP Does Not Match");
    }

    await redisClient.del(otpKey);

    const patientRegistrationKey = `patient-registration-data:${email}`;

    const redisPatientData = await redisClient.get(patientRegistrationKey);

    if (!redisPatientData) {
        throw new AppError(404, "Patient Doesn't Exist");
    }

    const patientPayload: IRegisterPatientPayload = JSON.parse(redisPatientData);

    const createdUser = await prisma.user.create({
        data: {
            name: patientPayload.name,
            email: patientPayload.email,
            password: patientPayload.password,
            role: Role.PATIENT,
            status: UserStatus.ACTIVE,
            emailVerified: true,
            patient: {
                create: {
                    name: patientPayload.name,
                    email: patientPayload.email,
                    contactNumber: patientPayload?.patient?.contactNumber || "",
                },
            },
        },
        omit: { password: true },
        include: { patient: true },
    });

    await redisClient.del(patientRegistrationKey);

    const tempatePath = path.join(
        process.cwd(),
        "src/app/templates/patient-welcome-email.ejs",
    );

    const templateData = {
        name: createdUser.name,
    };

    const html = await ejs.renderFile(tempatePath, templateData);

    await transporter.sendMail({
        from: config.email_sender,
        to: email,
        subject: "Welcome To PH Healthcare System",
        html,
    });

    const { patient, ...user } = createdUser;
    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
    };

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret as string,
        config.jwt_access_expires_in as SignOptions,
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret as string,
        config.jwt_refresh_expires_in as SignOptions,
    );

    return {
        user,
        patient,
        accessToken,
        refreshToken,
    };
};

const loginUser = async (payload: ILoginUserPayload) => {
    const { password } = payload;
    const email = payload.email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user) {
        throw new AppError(404, "User not found");
    }

    if (user.status === UserStatus.BLOCKED) {
        throw new AppError(403, "User is blocked");
    }

    if (user.isDeleted || user.status === UserStatus.DELETED) {
        throw new AppError(404, "User is deleted");
    }

    if (user.password === null && user.googleId !== null) {
        throw new AppError(
            400,
            "User Already Has Account Registered With Google. Try To Login With Google.",
        );
    }

    const isPasswordMatched = await bcrypt.compare(
        password,
        user.password as string,
    );

    if (!isPasswordMatched) {
        throw new AppError(401, "Invalid credentials");
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
    };

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret as string,
        config.jwt_access_expires_in as SignOptions,
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret as string,
        config.jwt_refresh_expires_in as SignOptions,
    );

    return {
        accessToken,
        refreshToken,
    };
};

const getMe = async (user: IRequestUser) => {
    const isUserExists = await prisma.user.findUnique({
        where: {
            id: user.userId,
        },
        include: {
            patient: true,
        },
        omit: {
            password: true,
        },
    });

    if (!isUserExists) {
        throw new AppError(404, "User not found");
    }

    return isUserExists;
};

const refreshToken = async (token: string) => {
    const verifiedRefreshToken = jwtUtils.verifyToken(
        token,
        config.jwt_refresh_secret as string,
    );

    if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
        throw new AppError(
            401,
            config.node_env === "development"
                ? verifiedRefreshToken.error
                : "Invalid refresh token",
        );
    }

    const data = verifiedRefreshToken.data as JwtPayload;

    const user = await prisma.user.findUnique({
        where: { id: data.userId },
    });

    if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
        throw new AppError(401, "User is inactive or not found");
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
    };

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret as string,
        config.jwt_access_expires_in as SignOptions,
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret || "",
        config.jwt_refresh_expires_in as SignOptions,
    );

    return {
        accessToken,
        refreshToken,
    };
};

const googleLogin = async (payload: IGoogleLoginPayload) => {
    let googleIdTokenPayload: TokenPayload | null | undefined = null;
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: payload.idToken,
            audience: config.google_client_id,
        });

        googleIdTokenPayload = ticket.getPayload();
    } catch (error) {
        console.log("Google ID Token Verification Failed", error);
        throw new AppError(401, "Invalid Or Expired Google Id Token");
    }

    if (!googleIdTokenPayload) {
        throw new AppError(401, "Invalid Or Expired Google Id Token");
    }

    if (!googleIdTokenPayload.email) {
        throw new AppError(400, "Google Email Not Found");
    }
    if (!googleIdTokenPayload.name) {
        throw new AppError(400, "Google Email User Name Not Found");
    }

    const ifPatientExistWithGoogleAuth = await prisma.user.findUnique({
        where: {
            email: googleIdTokenPayload.email,
            role: Role.PATIENT,
            googleId: googleIdTokenPayload.sub,
        },
    });

    let user = ifPatientExistWithGoogleAuth;

    if (!ifPatientExistWithGoogleAuth) {
        const ifPatientExistWithCredentials = await prisma.user.findUnique({
            where: {
                email: googleIdTokenPayload.email,
                role: Role.PATIENT,
                authProvider: AuthProvider.CREDENTIAL,
            },
        });

        if (ifPatientExistWithCredentials) {
            if (!ifPatientExistWithCredentials.emailVerified) {
                throw new AppError(400, "Email Not Verified");
            }

            if (ifPatientExistWithCredentials.status === UserStatus.BLOCKED) {
                throw new AppError(403, "User Is Blocked");
            }

            if (
                ifPatientExistWithCredentials.isDeleted ||
                ifPatientExistWithCredentials.status === UserStatus.DELETED
            ) {
                throw new AppError(404, "User Is Deleted");
            }

            user = await prisma.user.update({
                where: {
                    id: ifPatientExistWithCredentials.id,
                },

                data: {
                    googleId: googleIdTokenPayload.sub,
                },
            });
        } else {
            // Google Register
            user = await prisma.user.create({
                data: {
                    name: googleIdTokenPayload.name,
                    email: googleIdTokenPayload.email,
                    role: Role.PATIENT,
                    googleId: googleIdTokenPayload.sub,
                    authProvider: AuthProvider.GOOGLE,
                    emailVerified: true,
                    patient: {
                        create: {
                            name: googleIdTokenPayload.name,
                            email: googleIdTokenPayload.email,
                        },
                    },
                },
            });
            const tempatePath = path.join(
                process.cwd(),
                "src/app/templates/patient-welcome-email.ejs",
            );

            const templateData = {
                name: user.name,
            };

            const html = await ejs.renderFile(tempatePath, templateData);

            await transporter.sendMail({
                from: config.email_sender,
                to: user.email,
                subject: "Welcome To PH Healthcare System",
                html,
            });
        }
    }

    if (!user) {
        throw new AppError(404, "User Not Found");
    }

    if (user.status === UserStatus.BLOCKED) {
        throw new AppError(403, "User Is Blocked");
    }

    if (user.isDeleted || user.status === UserStatus.DELETED) {
        throw new AppError(404, "User Is Deleted");
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
    };

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret as string,
        config.jwt_access_expires_in as SignOptions,
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret as string,
        config.jwt_refresh_expires_in as SignOptions,
    );

    return {
        accessToken,
        refreshToken,
    };
};

const forgotPassword = async (payload: IForgotPasswordPayload) => {
    const { email } = payload;

    const isUserExist = await prisma.user.findUnique({
        where: {
            email,
        },
    });

    if (!isUserExist) {
        throw new AppError(404, "User Does Not Exist!");
    }

    if (isUserExist.status === "BLOCKED") {
        throw new AppError(403, "User is Blocked");
    }

    if (!isUserExist.emailVerified) {
        throw new AppError(400, "User Not Verified");
    }

    if (isUserExist.isDeleted || isUserExist.status === "DELETED") {
        throw new AppError(404, "User is Deleted");
    }

    if (isUserExist.googleId && isUserExist.authProvider === "GOOGLE") {
        throw new AppError(400, "User Has Account With Google");
    }

    const otp = crypto.randomInt(100000, 1000000).toString();

    const key = `forgor-password-otp:${isUserExist.email}`;

    const expirationSeconds = 5 * 60;

    await redisClient.set(key, otp, {
        expiration: {
            type: "EX",
            value: expirationSeconds,
        },
    });

    const tempatePath = path.join(
        process.cwd(),
        "src/app/templates/forgot-password.ejs",
    );

    const templateData = {
        name: isUserExist.name,
        otp,
        expirationMinutes: expirationSeconds / 60,
    };

    const html = await ejs.renderFile(tempatePath, templateData);

    await transporter.sendMail({
        from: config.email_sender,
        to: isUserExist.email,
        subject: "Forgot Password",
        html,
    });
};

const resetPassword = async (payload: IResetPasswordPayload) => {
    const { email, otp, newPassword } = payload;

    const isUserExist = await prisma.user.findUnique({
        where: {
            email,
        },
    });

    if (!isUserExist) {
        throw new AppError(404, "User Does Not Exist!");
    }

    if (isUserExist.status === "BLOCKED") {
        throw new AppError(403, "User is Blocked");
    }

    if (!isUserExist.emailVerified) {
        throw new AppError(400, "User Not Verified");
    }

    if (isUserExist.isDeleted || isUserExist.status === "DELETED") {
        throw new AppError(404, "User is Deleted");
    }

    if (isUserExist.googleId && isUserExist.authProvider === "GOOGLE") {
        throw new AppError(400, "User Has Account With Google");
    }

    const key = `forgor-password-otp:${isUserExist.email}`;

    const redisOtp = await redisClient.get(key);

    if (!redisOtp) {
        throw new AppError(400, "Invalid OTP");
    }

    if (redisOtp !== otp) {
        throw new AppError(400, "OTP Does Not Match");
    }

    const hashedNewPassword = await bcrypt.hash(
        newPassword,
        Number(config.bcrypt_salt_rounds),
    );

    await prisma.user.update({
        where: {
            email: isUserExist.email,
        },
        data: {
            password: hashedNewPassword,
        },
    });

    await redisClient.del([key]);

    const tempatePath = path.join(
        process.cwd(),
        "src/app/templates/reset-password-success.ejs",
    );

    const templateData = {
        name: isUserExist.name,
    };

    const html = await ejs.renderFile(tempatePath, templateData);

    await transporter.sendMail({
        from: config.email_sender,
        to: isUserExist.email,
        subject: "Password Changed",
        html,
    });
};

export const AuthService = {
    registerPatient,
    loginUser,
    getMe,
    refreshToken,
    googleLogin,
    forgotPassword,
    resetPassword,
    verifyPatientEmail,
};