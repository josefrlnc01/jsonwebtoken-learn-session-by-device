import { app, PORT } from './server.js'
import express from 'express'
import jwt from 'jsonwebtoken'
import { corsMiddleware } from './middlewares/cors.js'
import { authToken } from './middlewares/authToken.js'
import dotenv from 'dotenv'
import { db } from './db/db.js'
import cookieParser from 'cookie-parser'
import { hashPassword, verifyPassword } from './utils/passwords.js'
import { hashToken} from './utils/tokens.js'


dotenv.config()
app.use(express.json())
app.use(corsMiddleware())
app.use(cookieParser())



//Esta clave secreta siempre debe definirse en .env y no debe ser accesible
const access_key = process.env.SECRET_ACCESS_KEY
const refresh_key = process.env.SECRET_REFRESH_KEY


//Inicio de sesión para obtención del token
app.post('/login', async (req, res) => {
    const {email, password} = req.body
    const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)
    
    if (!user) {
        return res.status(401).json({error : 'Usuario no registrado'})
    }

    //Comprobación de password en form vs password cifrada almacenada
    const isValidPassword = await verifyPassword(password, user.password)
 
    if (!isValidPassword) {
        return res.status(401).json({error : 'Password incorrecto'})
    }

    
    //Firma del token con valores introducidos por el usuario + clave secreta
    //Nunca guardamos passwords
    const refreshToken = jwt.sign({ 
        userId: user.id,
        sessionId : crypto.randomUUID()
     }, refresh_key, {
        expiresIn: '90d'
    })

    const accessToken = jwt.sign({
        userId: user.id
    }, access_key, {
        expiresIn: '10m'
    })

    const hashedToken = hashToken(refreshToken)

    //Adición del refresh token a la bd
    db.prepare(`
        INSERT INTO refresh_tokens (user_id, token_hash, device)
        VALUES (?,?,?)
        `).run(user.id, 
            hashedToken,
        req.headers['user-agent'] || ['unknown'])


    //Envío de refresh token por cookies
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        sameSite: 'strict'
    })


    //Devolvemos el token
    res.json({ accessToken })
})


app.get('/login', authToken, (req, res) => {
    res.json({ message: 'Hello World' })
})


//Usamos el middleware de autenticación en las rutas deseadas
app.get('/profile', authToken, (req, res) => {
    res.json({ message: 'Acceso permitido', user: req.user })
})



app.listen(PORT, () => console.log(`Listening on ${PORT}`))



app.post('/register', async (req, res) => {
    const {name, email, password } = req.body

    const userRegistered = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)
    if (userRegistered) {
        return res.status(401).json({error : 'Usuario ya registrado'})
    }

    const hashedPassword = await hashPassword(password)
    console.log(hashedPassword)
    db.prepare(`INSERT INTO users(name, email, password)
    VALUES (?, ?, ?)
    `).run(name, email, hashedPassword)
   

    const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)

    res.json({ user })
})



//Ruta de obtención de nuevo token de acceso
app.post('/refresh', async (req, res) => {
    const token = req.cookies.refreshToken

    if (!token) return res.sendStatus(401)

    //Obtención del payload de refreshToken
    let payload 
    try {
        payload = jwt.verify(token, refresh_key)
    } catch(error) {
        return res.sendStatus(403)
    }

    //Hasheo de token y comprobación de sesión activa 
    const tokenHash = hashToken(token)
    const session = db.prepare(`
        SELECT * FROM refresh_tokens 
        WHERE token_hash = ?
        AND revoked = 0
        `).get(tokenHash)

    if (!session) {
        db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
            `).run(payload.userId)
    }

    //Rotación y creación de nuevo refresh token
    db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
        `).run(session.id)

    const newRefreshToken = jwt.sign({id : payload.userId, sessionId : crypto.randomUUID()}, refresh_key, {
        expiresIn : '90d'
    })

    //Adición del nuevo refresh token a la bd
    db.prepare(`
        INSERT INTO refresh_tokens(user_id, token_hash, device)
        VALUES(?,?,?)
        `).run(
            payload.id,
            hashToken(newRefreshToken),
            session.device
        )

    const accessToken = jwt.sign({id : payload.userId}, access_key, {
        expiresIn : '10m'
    })

    res.cookie('refreshToken', newRefreshToken, {
        httpOnly : true,
        sameSite : 'strict'
    })

    res.json({accessToken})
})


app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken
    
    let payload 

    try {
        payload = jwt.verify(refreshToken, refresh_key)
    } catch (error) {
        return res.sendStatus(401)
    }
    if (refreshToken) {
        const hashedToken = hashToken(refreshToken)
        db.prepare(`DELETE FROM refresh_tokens
            WHERE token_hash = ? 
            AND user_id = ?
        `).run(hashedToken, payload.userId)
    }

    res.clearCookie('refreshToken')
    res.sendStatus(204)
})








