import bcrypt from "bcrypt";
import prisma from "../lib/prisma.js";
import jwt from 'jsonwebtoken'

export const register = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await prisma.user.create({
            data: {
                username,
                email,
                password: hashedPassword
            }
        })

        if (newUser) {
            res.status(201).json({ response: "success", message: "User Created Successfully" });
        } else {
            res.status(201).json({ response: "failed", message: "Something went wrong" });
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({ response: "failed", message: "Failed to Create User" })
    }
};

export const login = async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: {
                username: username
            }
        })

        if (!user) {
            return res.status(404).json({ response: "failed", message: "Invalid Credentials" })
        } else {
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) return res.status(401).json({ response: "failed", message: "Invalid Credentials" })

            const age = 1000 * 60 * 60 * 24 * 7;

            const token = jwt.sign({
                id: user.id
            }, process.env.JTW_SECRET_KEY, { expiresIn: age })

            const { password: userPassword, ...userInfo } = user

            res.status(200).cookie("token", token, { httpOnly: true, maxAge: age }).json({ response: "success", message: "Login Successfull", data: userInfo })
        }

    } catch (err) {
        console.log(err)
        res.status(500).json({ response: "failed", message: "Failed to Login" })
    }
};

export const logout = (req, res) => {
    res.clearCookie("token").status(200).json({ response: "success", message: "Logged out successfully" })
};