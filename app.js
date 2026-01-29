import { app, PORT } from './server.js'
import express from 'express'
import jwt from 'jsonwebtoken'
import { corsMiddleware } from './middlewares/cors.js'
import { authToken } from './middlewares/authToken.js'
import dotenv from 'dotenv'
import { db } from './db/db.js'
import cookieParser from 'cookie-parser'
import { hashPassword, verifyPassword } from './utils/passwords.js'
import { hashToken } from './utils/tokens.js'



dotenv.config()
app.use(express.json())
app.use(corsMiddleware())
app.use(cookieParser())



//Esta clave secreta siempre debe definirse en .env y no debe ser accesible
export const access_key = process.env.SECRET_ACCESS_KEY
export const refresh_key = process.env.SECRET_REFRESH_KEY


//Inicio de sesión para obtención del token
app.post('/login', async (req, res) => {
    const { email, password } = req.body
    const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)

    if (!user) {
        return res.status(401).json({ error: 'Usuario no registrado' })
    }
  
    //Comprobación de password en form vs password cifrada almacenada
    const isValidPassword = await verifyPassword(password, user.password)

    if (!isValidPassword) {
        return res.status(401).json({ error: 'Password incorrecto' })
    }


    //Revocamos sesiones previas por dispositivo
    const revoke = db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
        AND device = ?
        `).run(user.id, req.headers['user-agent'])


    console.log('Revocación terminada')
    console.log(revoke.changes)


    //Firma del token con valores introducidos por el usuario + clave secreta
    //Nunca guardamos passwords
    const sessionId = crypto.randomUUID()
    const refreshToken = jwt.sign({
        userId: user.id,
        sessionId
    }, refresh_key, {
        expiresIn: '90d'
    })

    const accessToken = jwt.sign({
        userId: user.id
    }, access_key, {
        expiresIn: '10m'
    })


    //Adición del refresh token hasheado a la bd
    const hashedToken = hashToken(refreshToken)
    db.prepare(`
        INSERT INTO refresh_tokens (user_id, token_hash, session_uuid, device)
        VALUES (?,?,?,?)
        `).run(user.id,
        hashedToken,
        sessionId,
        req.headers['user-agent'] || 'unknown')


    //Envío de refresh token por cookies
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        sameSite: 'strict',
        secure: false //en desarrollo true
    })


    //Devolvemos el access token al cliente
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
    const { name, email, password } = req.body

    const userRegistered = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)
    if (userRegistered) {
        return res.status(401).json({ error: 'Usuario ya registrado' })
    }

    const hashedPassword = await hashPassword(password)
    
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
    } catch (error) {
        return res.sendStatus(403)
    }

    //Hasheo de token y comprobación de sesión activa 
    const tokenHash = hashToken(token)
    const session = db.prepare(`
        SELECT * FROM refresh_tokens 
        WHERE token_hash = ?
        AND revoked = 0
        `).get(tokenHash)



    if (!session || session.uuid !== payload.sessionId) {
        //Si se ha revocado el token = comprometido, revocamos todo y limpiamos cookies
        db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
            `).run(payload.userId)

        res.clearCookie('refreshToken')
        return res.status(403).json({ error: 'Se ha detectado un uso de un refresh token antiguo. Vuelve a iniciar sesión' })
    }

    //Rotación y creación de nuevo refresh token
    db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE id = ?
        `).run(session.id)

    const newRefreshToken = jwt.sign({ id: payload.userId, sessionId: crypto.randomUUID() }, refresh_key, {
        expiresIn: '90d'
    })

    //Adición del nuevo refresh token a la bd
    db.prepare(`
        INSERT INTO refresh_tokens(user_id, token_hash, device)
        VALUES(?,?,?)
        `).run(
        payload.userId,
        hashToken(newRefreshToken),
        session.device
    )

    const accessToken = jwt.sign({ id: payload.userId }, access_key, {
        expiresIn: '10m'
    })

    res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        sameSite: 'strict',
        secure: false //en desarrollo true
    })

    res.json({ accessToken })
})


app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken

    if (!refreshToken) {
        return res.sendStatus(204)
    }


    let payload
    try {
        payload = jwt.verify(refreshToken, refresh_key)
    } catch (error) {
        //Si el token es inválido o expirado se hace logout igualmente
        res.clearCookie('refreshToken')
        return res.sendStatus(204)
    }

    //Revocamos la sesión
    db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
        AND session_uuid = ?
        `).run(payload.userId, payload.sessionId)


    res.clearCookie('refreshToken')
    res.sendStatus(204)
})



app.post('/logout-global', (req, res) => {
    const refreshToken = req.cookies.refreshToken

    if (refreshToken) {
        let payload
        try {
            payload = jwt.verify(refreshToken, refresh_key)
        } catch (error) {
            res.clearCookie('refreshToken')
            return res.sendStatus(204)
        }

        db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
        `).run(payload.userId)
    }


    res.clearCookie('refreshToken')
    res.sendStatus(204)
})




app.get('/sessions', authToken, (req, res) => {
    const user = req.user
    console.log('user', user)
    const sessions = db.prepare(`
        SELECT id, session_uuid, device
        FROM refresh_tokens
        WHERE user_id = ? 
        AND revoked = 0
        `).all(user.userId)
        console.log(sessions)
    res.json(sessions)
})


app.post('/revoke-sessions', authToken, (req, res) => {
    const {device} = req.body

    if (!device) {
        return res.status(400).json({error : 'Debes introducir el dispositivo del que quieres cerrar la sesión'})
    }
    const user = req.user
    const activeSessions = db.prepare(`
        SELECT device
        FROM refresh_tokens
        WHERE user_id = ?
        AND revoked = 0
        `).all(user.userId)
        console.log(activeSessions)

   
    const devices = activeSessions.map(s => s.device)

    if (!devices.includes(device)) {
        return res.status(404).json({error : 'Este dispositivo no se ha logueado con tu cuenta'})
    }

    db.prepare(`
        UPDATE refresh_tokens
        SET revoked = 1
        WHERE user_id = ?
        AND device = ?
        `).run(user.userId, device)

    res.sendStatus(204)
})


const device1 = 'PostmanRuntime/7.51.0'
