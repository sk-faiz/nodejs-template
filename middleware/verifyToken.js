import { response } from "express";
import jwt from "jsonwebtoken"

export const verifyToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) return res.status(401).json({ response: "failed", message: "Not Authenticated" })

    jwt.verify(token, process.env.JTW_SECRET_KEY, async (err, payload) => {
        if (err) return res.status(403).json({ response: "failed", message: "Token is not valid" })
        req.userId = payload.id;
        next()
    })
}