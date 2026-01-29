import { access_key } from "../app.js"
import jwt from 'jsonwebtoken'

export function authToken (req, res, next) {
    const headers = req.headers.authorization

    const token = headers && headers.split(' ')[1]

    

    if (!token) {
        const error = new Error('No estás autorizado a ver el contenido')
        return res.status(401).json({error : error.message})
    }

    try {
        const decoded = jwt.verify(token, access_key)
        req.user = decoded
        next()
    } catch (error) {
        return res.status(403).json({error : 'Token inválido o expirado'})
    }

    
}
