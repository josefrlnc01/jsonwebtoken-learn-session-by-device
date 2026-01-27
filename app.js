import { app, PORT } from './server.js'
import express from 'express'
import jwt from 'jsonwebtoken'
import { corsMiddleware } from './middlewares/cors.js'
import { authToken } from './middlewares/authToken.js'
import dotenv from 'dotenv'
import { db } from './db/db.js'
import cookieParser from 'cookie-parser'
import { hashPassword, verifyPassword } from './utils/passwords.js'

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
    const refreshToken = jwt.sign({ id: user.id }, refresh_key, {
        expiresIn: '90d'
    })

    const accessToken = jwt.sign({
        id: user.id,
        role: 'user'
    }, access_key, {
        expiresIn: '10m'
    })

    //Adición del refresh token a la bd
    db.prepare(`
        UPDATE users
        SET refresh_token = ?
        WHERE email = ?
        `).run(refreshToken, email)


    //Envío de refrsh token por cookies
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
app.post('/refresh', (req, res) => {
    //Comprobacion de existencia de refreshToken en cookies
    const refreshToken = req.cookies.refreshToken
    if (!refreshToken) return res.sendStatus(401)

    //Comprobación de usuario existente
    const user = db.prepare(`SELECT id, email FROM users
        WHERE refresh_token = (?)
        `).get(refreshToken)


    if (!user) return res.sendStatus(403)


    try {
        //Verificación del token de refresco
        const decoded = jwt.verify(refreshToken, refresh_key)

        //Creación del nuevo token de acceso
        const newAccessToken = jwt.sign({ id: decoded.id }, access_key, {
            expiresIn: '10m'
        })

        //Creación del nuevo token de refresh
        const newRefreshToken = jwt.sign({id : decoded.id}, refresh_key, {
            expiresIn : '90d'
        })

        //Modificación del refresh en bd
        db.prepare(`
            UPDATE users
            SET refresh_token = ?
            WHERE refresh_token = ?
            `).run(newRefreshToken, refreshToken)

        //Envío nuevamente del refresh por cookies
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly : true,
            sameSite : 'strict'
        })

        res.json({ accessToken: newAccessToken })
    } catch (error) {
        return res.sendStatus(403)
    }
})


app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken
    if (refreshToken) {
        const user = req.user
        db.prepare(`UPDATE users SET refresh_token = NULL
            WHERE refresh_token = ?
        `).run(refreshToken)
    }

    res.clearCookie('refreshToken')
    res.sendStatus(204)
})








